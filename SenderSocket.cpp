#include "SenderSocket.h"
#include <stdio.h>
#include <algorithm>

// initialize socket
SenderSocket::SenderSocket(): sock(INVALID_SOCKET), connected(false), estRTT(0.0), devRTT(0.0), RTO(DEFAULT_RTO), baseSeq(0), nextSeq(0), numTimeouts(0), numFastRetx(0), senderWnd(1), effWnd(1), finalChecksum(0),
    hStatsThread(NULL), hStopEvent(NULL), pending(nullptr), empty(NULL), full(NULL), eventQuit(NULL), socketReceiveReady(NULL), hWorkerThread(NULL), sndBase(0), nextToSend(0), lastReleased(0), dupAckCount(0), timerExpire(0.0), failStatus(0) {
    memset(&server, 0, sizeof(server));
    t0 = std::chrono::steady_clock::now();
}

SenderSocket::~SenderSocket() {
    if (eventQuit != NULL) SetEvent(eventQuit);
    if (hStopEvent != NULL) SetEvent(hStopEvent);

    if (hWorkerThread != NULL) {
        WaitForSingleObject(hWorkerThread, INFINITE);
        CloseHandle(hWorkerThread);
        hWorkerThread = NULL;
    }
    if (hStatsThread != NULL) {
        WaitForSingleObject(hStatsThread, INFINITE);
        CloseHandle(hStatsThread);
        hStatsThread = NULL;
    }
    if (hStopEvent != NULL) {
        CloseHandle(hStopEvent);
        hStopEvent = NULL;
    }
    if (eventQuit != NULL) {
        CloseHandle(eventQuit);
        eventQuit = NULL;
    }
    if (socketReceiveReady != NULL) {
        CloseHandle(socketReceiveReady);
        socketReceiveReady = NULL; 
    }
    if (empty != NULL) {
        CloseHandle(empty);
        empty = NULL;
    }
    if (full != NULL) {
        CloseHandle(full);
        full = NULL; 
    }
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }

    delete[] pending;
    pending = nullptr;
}

// if program exits prematurely
double SenderSocket::Now() const {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

void SenderSocket::UpdateRTO(double sampleRTT) {
    if (estRTT == 0.0) {
        estRTT = sampleRTT;
        devRTT = sampleRTT / 2.0;
    } else {
        estRTT = 0.875 * estRTT + 0.125 * sampleRTT;
        devRTT = 0.75 * devRTT + 0.25 * fabs(sampleRTT - estRTT);
    }

    // prevent deviation from falling below 10ms
    RTO = estRTT + 4.0 * max(devRTT, 0.010);
}

DWORD WINAPI SenderSocket::StatsThreadEntry(LPVOID param) {
    SenderSocket* ss = (SenderSocket*)param;
    ss->StatsWorker();
    return 0;
}

void SenderSocket::StatsWorker() {
    DWORD prevBase = 0;
    auto prevTime = std::chrono::steady_clock::now();
    int tick = 1;

    while (true) {
        double wait = 2.0 * tick - Now();
        DWORD ms = wait > 0 ? (DWORD)(wait * 1000) : 0;
        if (WaitForSingleObject(hStopEvent, ms) != WAIT_TIMEOUT) break;
        tick++;
        auto curTime = std::chrono::steady_clock::now();
        double dSec = std::chrono::duration<double>(curTime - prevTime).count();
        double totSec = std::chrono::duration<double>(curTime - t0).count();

        DWORD curBase = baseSeq.load();
        DWORD curNext = nextSeq.load();
        int timeouts = numTimeouts.load();
        int fastRetx = numFastRetx.load();

        int payloadSize = MAX_PKT_SIZE - sizeof(SenderDataHeader);
        double deltaBytes = (double)(curBase - prevBase) * payloadSize;
        double speedMbps = (dSec > 0) ? ((deltaBytes * 8.0) / (dSec * 1e6)) : 0.0;
        double mbAcked = ((double)curBase * payloadSize) / (1024.0 * 1024.0);

        printf("[%2d] B %5d (%4.1f MB) N %5d T %d F %d W %d S %6.3f Mbps RTT %.3f\n", (int)totSec, curBase, mbAcked, curNext, timeouts, fastRetx, effWnd, speedMbps, estRTT);

        prevBase = curBase;
        prevTime = curTime;
    }
}

DWORD WINAPI SenderSocket::WorkerThreadEntry(LPVOID param) {
    SenderSocket* ss = (SenderSocket*)param;
    ss->WorkerRun();
    return 0;
}

void SenderSocket::WorkerRun() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    // DOOOO real loop comes next
    WaitForSingleObject(eventQuit, INFINITE);
}

int SenderSocket::Open(const char* targetHost, int port, int senderWindow, LinkProperties* lp) {
    if (connected) return ALREADY_CONNECTED;
    senderWnd = senderWindow;

    // builds destination address
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((u_short)port);

    // takes in the string as an IP
    DWORD ip = inet_addr(targetHost);
    if (ip == INADDR_NONE) {
        struct hostent* remote = gethostbyname(targetHost);
        if (remote == NULL) return INVALID_NAME;
        memcpy(&server.sin_addr, remote->h_addr, remote->h_length);
    } else {
        server.sin_addr.S_un.S_addr = ip;
    }

    // create and bind UDP socket to port 0
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return FAILED_SEND;

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);

    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        return FAILED_SEND;
    }

    // SYN
    RTO = max(1.0, 2.0 * (double)lp->RTT);

    // router buffer
    lp->bufferSize = senderWindow + MAX_ATTEMPTS;
    SenderSynHeader ssh;
    ssh.sdh.flags.SYN = 1;
    ssh.sdh.seq = 0;
    ssh.lp = *lp;

    ReceiverHeader rh;
    double rttSample = 0;
    int status = SendAndWait("SYN", 0, (const char*)&ssh, sizeof(ssh), SYN_MAX_ATTEMPTS, true, false, rh, rttSample);
    if (status != STATUS_OK) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        return status;
    }

    if (rttSample > 0) {
        estRTT = rttSample;
        devRTT = 0.0;
    } else {
        estRTT = lp->RTT;
        devRTT = 0.0;
    }

    RTO = estRTT + 4.0 * max(devRTT, 0.010);
    effWnd = min(senderWnd, (int)rh.recvWnd);

    // bigger kernel buffers
    int kb = 20000000;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&kb, sizeof(kb));
    kb = 20000000;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&kb, sizeof(kb));

    // pipeline state
    pending = new Packet[senderWnd];
    eventQuit = CreateEvent(NULL, TRUE, FALSE, NULL); // manual-reset
    socketReceiveReady = CreateEvent(NULL, FALSE, FALSE, NULL); // auto-reset
    WSAEventSelect(sock, socketReceiveReady, FD_READ);

    empty = CreateSemaphore(NULL, 0, senderWnd, NULL);
    full = CreateSemaphore(NULL, 0, senderWnd, NULL);
    lastReleased = effWnd;
    ReleaseSemaphore(empty, effWnd, NULL);

    baseSeq = 0;
    nextSeq = 0;
    sndBase = 0;
    nextToSend = 0;
    dupAckCount = 0;
    timerExpire = 0.0;
    numTimeouts = 0;
    numFastRetx = 0;
    failStatus = 0;
    connected = true;
    tStart = std::chrono::steady_clock::now();

    hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    hStatsThread = CreateThread(NULL, 0, StatsThreadEntry, this, 0, NULL);
    hWorkerThread = CreateThread(NULL, 0, WorkerThreadEntry, this, 0, NULL);

    return STATUS_OK;
}

int SenderSocket::Send(const char* buf, int bytes) {
    if (!connected) return NOT_CONNECTED;

    HANDLE arr[] = { eventQuit, empty };
    DWORD r = WaitForMultipleObjects(2, arr, FALSE, INFINITE);
    
    if (r == WAIT_OBJECT_0) {
        int fs = failStatus.load();
        return fs != 0 ? fs : NOT_CONNECTED;
    }

    DWORD seq = nextSeq.load();
    Packet* p = &pending[seq % senderWnd];

    SenderDataHeader* sdh = (SenderDataHeader*)p->pkt;
    sdh->flags = Flags();
    sdh->seq = seq;
    memcpy(sdh + 1, buf, bytes);

    p->type = 0;
    p->size = (int)sizeof(SenderDataHeader) + bytes;
    p->attempts = 0;

    nextSeq++;
    ReleaseSemaphore(full, 1, NULL);
    return STATUS_OK;
}

int SenderSocket::Close(double* elapsedTime) {
    if (!connected) return NOT_CONNECTED;

    // wait until every data packet is ACKed
    while (baseSeq.load() < nextSeq.load()) {
        int fs = failStatus.load();
        if (fs != 0) return fs;
        Sleep(1);
    }
    tEnd = std::chrono::steady_clock::now();

    // stop worker and stats
    SetEvent(eventQuit);
    WaitForSingleObject(hWorkerThread, INFINITE);
    CloseHandle(hWorkerThread);
    hWorkerThread = NULL;

    SetEvent(hStopEvent);
    WaitForSingleObject(hStatsThread, INFINITE);
    CloseHandle(hStatsThread);
    hStatsThread = NULL;

    // FIN
    DWORD finSeq = nextSeq.load();
    SenderDataHeader sdh;
    sdh.flags.FIN = 1;
    sdh.seq = finSeq;

    ReceiverHeader rh;
    double rttSample = 0;
    int status = SendAndWait("FIN", finSeq, (const char*)&sdh, sizeof(sdh), MAX_ATTEMPTS, false, true, rh, rttSample);
    
    if (status != STATUS_OK) return status;

    finalChecksum = rh.recvWnd;
    printf("[%5.2f] <-- FIN-ACK %d window %X\n", Now(), rh.ackSeq, finalChecksum);

    if (elapsedTime != nullptr) *elapsedTime = std::chrono::duration<double>(tEnd - tStart).count();

    connected = false;
    closesocket(sock);
    sock = INVALID_SOCKET;
    return STATUS_OK;
}

int SenderSocket::SendAndWait(const char* name, DWORD seq, const char* pkt, int len, int maxAttempts, bool isSYN, bool isFIN, ReceiverHeader& rh, double& rttSample) {
    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
        auto sendTime = std::chrono::steady_clock::now();
        if (sendto(sock, pkt, len, 0, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) return FAILED_SEND;
        double deadline = Now() + RTO;

        while (true) {
            double remaining = deadline - Now();
            if (remaining <= 0) break;

            fd_set fd;
            FD_ZERO(&fd);
            FD_SET(sock, &fd);
            timeval tv;
            tv.tv_sec = (long)remaining;
            tv.tv_usec = (long)((remaining - tv.tv_sec) * 1e6);

            int ready = select(0, &fd, NULL, NULL, &tv);
            if (ready == SOCKET_ERROR) return FAILED_RECV;
            if (ready == 0) break;

            struct sockaddr_in from;
            int fromLen = sizeof(from);
            int bytes = recvfrom(sock, (char*)&rh, sizeof(rh), 0, (struct sockaddr*)&from, &fromLen);
            if (bytes == SOCKET_ERROR) return FAILED_RECV;
            if (bytes != sizeof(ReceiverHeader)) continue;
            if (rh.flags.magic != MAGIC_PROTOCOL || !rh.flags.ACK) continue;

            if (isSYN) {
                if (rh.flags.SYN) {
                    if (attempt == 1)
                        rttSample = std::chrono::duration<double>(std::chrono::steady_clock::now() - sendTime).count();
                    return STATUS_OK;
                }
            } else if (isFIN) {
                if (rh.flags.FIN) return STATUS_OK;
            } else {
                if (rh.ackSeq == seq + 1) {
                    if (attempt == 1) {   // Karn's rule: only sample non-retransmitted packets
                        rttSample = std::chrono::duration<double>(std::chrono::steady_clock::now() - sendTime).count();
                        UpdateRTO(rttSample);
                    }
                    return STATUS_OK;
                }
            }
        }
        if (!isSYN && !isFIN) numTimeouts++;
    }
    return TIMEOUT;
}
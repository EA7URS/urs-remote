#ifndef WSJTXMESSAGE_H
#define WSJTXMESSAGE_H

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QTime>

namespace WsjtxMessage {

static constexpr quint32 Magic = 0xadbccbda;
static constexpr quint32 Schema = 3;

enum Type : quint32 { Heartbeat = 0, Status = 1, Decode = 2,
                      QsoLogged = 5, Close = 6, LoggedAdif = 12 };

struct StatusFields {
    quint64 dialFrequency = 0;
    QString mode, dxCall, report, txMode;
    bool txEnabled = false, transmitting = false, decoding = false;
    quint32 rxDf = 0, txDf = 0;
    QString deCall, deGrid, dxGrid;
    bool txWatchdog = false;
    QString subMode;
    bool fastMode = false;
    quint8 specialOperationMode = 0;
    quint32 frequencyTolerance = 0, trPeriod = 0;
    QString configurationName, txMessage;
};

struct DecodeFields {
    bool isNew = true;
    QTime time;
    qint32 snr = 0;
    double deltaTime = 0;
    quint32 deltaFrequency = 0;
    QString mode, message;
    bool lowConfidence = false, offAir = false;
};

struct QsoFields {
    QDateTime dateOff;
    QString dxCall, dxGrid;
    quint64 txFrequency = 0;
    QString mode, reportSent, reportReceived, txPower, comments, name;
    QDateTime dateOn;
    QString operatorCall, myCall, myGrid, exchangeSent, exchangeReceived,
            propagationMode;
};

QByteArray heartbeat(const QString &id, quint32 maxSchema,
                     const QString &version, const QString &revision);
QByteArray status(const QString &id, const StatusFields &fields);
QByteArray decode(const QString &id, const DecodeFields &fields);
QByteArray qsoLogged(const QString &id, const QsoFields &fields);
QByteArray close(const QString &id);
QByteArray loggedAdif(const QString &id, const QByteArray &adifDocument);

} // namespace WsjtxMessage

#endif

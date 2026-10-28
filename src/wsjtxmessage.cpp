#include "wsjtxmessage.h"

#include <QDataStream>

namespace {
void initialize(QDataStream &out, quint32 type, const QString &id)
{
    // WSJT-X NetworkMessage schema 3 uses the Qt 5.4 stream representation.
    out.setVersion(QDataStream::Qt_5_4);
    out.setByteOrder(QDataStream::BigEndian);
    out << WsjtxMessage::Magic << WsjtxMessage::Schema << type << id.toUtf8();
}

QByteArray utf8(const QString &value) { return value.toUtf8(); }
}

namespace WsjtxMessage {

QByteArray heartbeat(const QString &id, quint32 maxSchema,
                     const QString &version, const QString &revision)
{
    QByteArray packet;
    QDataStream out(&packet, QIODevice::WriteOnly);
    initialize(out, Heartbeat, id);
    out << maxSchema << utf8(version) << utf8(revision);
    return packet;
}

QByteArray status(const QString &id, const StatusFields &f)
{
    QByteArray packet;
    QDataStream out(&packet, QIODevice::WriteOnly);
    initialize(out, Status, id);
    out << f.dialFrequency << utf8(f.mode) << utf8(f.dxCall) << utf8(f.report)
        << utf8(f.txMode) << f.txEnabled << f.transmitting << f.decoding
        << f.rxDf << f.txDf << utf8(f.deCall) << utf8(f.deGrid)
        << utf8(f.dxGrid) << f.txWatchdog << utf8(f.subMode) << f.fastMode
        << f.specialOperationMode << f.frequencyTolerance << f.trPeriod
        << utf8(f.configurationName) << utf8(f.txMessage);
    return packet;
}

QByteArray decode(const QString &id, const DecodeFields &f)
{
    QByteArray packet;
    QDataStream out(&packet, QIODevice::WriteOnly);
    initialize(out, Decode, id);
    out << f.isNew << f.time << f.snr << f.deltaTime << f.deltaFrequency
        << utf8(f.mode) << utf8(f.message) << f.lowConfidence << f.offAir;
    return packet;
}

QByteArray qsoLogged(const QString &id, const QsoFields &f)
{
    QByteArray packet;
    QDataStream out(&packet, QIODevice::WriteOnly);
    initialize(out, QsoLogged, id);
    out << f.dateOff << utf8(f.dxCall) << utf8(f.dxGrid) << f.txFrequency
        << utf8(f.mode) << utf8(f.reportSent) << utf8(f.reportReceived)
        << utf8(f.txPower) << utf8(f.comments) << utf8(f.name) << f.dateOn
        << utf8(f.operatorCall) << utf8(f.myCall) << utf8(f.myGrid)
        << utf8(f.exchangeSent) << utf8(f.exchangeReceived)
        << utf8(f.propagationMode);
    return packet;
}

QByteArray close(const QString &id)
{
    QByteArray packet;
    QDataStream out(&packet, QIODevice::WriteOnly);
    initialize(out, Close, id);
    return packet;
}

QByteArray loggedAdif(const QString &id, const QByteArray &adifDocument)
{
    QByteArray packet;
    QDataStream out(&packet, QIODevice::WriteOnly);
    initialize(out, LoggedAdif, id);
    out << adifDocument;
    return packet;
}

} // namespace WsjtxMessage

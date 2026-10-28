#include "wsjtxmessage.h"

#include <QDataStream>
#include <QBuffer>
#include <QDebug>
#include <cstdlib>

namespace {
struct Header { quint32 magic, schema, type; QByteArray id; };

void readHeader(const QByteArray &packet, QBuffer *buffer, QDataStream *in, Header *header)
{
    buffer->setData(packet);
    buffer->open(QIODevice::ReadOnly);
    in->setDevice(buffer);
    in->setVersion(QDataStream::Qt_5_4);
    in->setByteOrder(QDataStream::BigEndian);
    *in >> header->magic >> header->schema >> header->type >> header->id;
}

void require(bool condition, const char *message)
{
    if (!condition) { qCritical() << message; ::exit(1); }
}

void requireComplete(const QDataStream &in, const char *message)
{
    require(in.status() == QDataStream::Ok && in.atEnd(), message);
}

void checkHeader(const Header &h, quint32 type)
{
    require(h.magic == WsjtxMessage::Magic, "bad magic");
    require(h.schema == WsjtxMessage::Schema, "bad schema");
    require(h.type == type, "bad message type");
    require(h.id == QByteArray("wfweb"), "ID is not protocol utf8/QByteArray");
}
}

int main()
{
    Header h{}; QBuffer buffer; QDataStream in;

    {
        auto packet = WsjtxMessage::heartbeat("wfweb", 3, "0.9.0", "test");
        readHeader(packet, &buffer, &in, &h); quint32 maxSchema; QByteArray version, revision;
        in >> maxSchema >> version >> revision;
        checkHeader(h, 0); require(maxSchema == 3 && version == "0.9.0" && revision == "test", "bad heartbeat fields"); requireComplete(in, "heartbeat malformed or trailing data");
        buffer.close();
    }
    {
        WsjtxMessage::StatusFields f; f.dialFrequency=14074000; f.mode="FT8"; f.txMode="FT8"; f.deCall="N0CALL"; f.deGrid="FN42";
        auto packet=WsjtxMessage::status("wfweb",f); readHeader(packet, &buffer, &in, &h);
        quint64 frequency; QByteArray mode,dxCall,report,txMode,deCall,deGrid,dxGrid,subMode,configuration,txMessage;
        bool txEnabled,transmitting,decoding,watchdog,fastMode; quint32 rxDf,txDf,tolerance,period; quint8 special;
        in>>frequency>>mode>>dxCall>>report>>txMode>>txEnabled>>transmitting>>decoding>>rxDf>>txDf>>deCall>>deGrid>>dxGrid>>watchdog>>subMode>>fastMode>>special>>tolerance>>period>>configuration>>txMessage;
        checkHeader(h,1); require(frequency==14074000 && mode=="FT8" && txMode=="FT8","bad status mode/frequency"); require(deCall=="N0CALL"&&deGrid=="FN42"&&dxGrid.isEmpty(),"bad or missing status station/grid fields"); require(!txEnabled&&!transmitting&&!decoding&&!watchdog&&!fastMode&&rxDf==0&&txDf==0&&special==0&&tolerance==0&&period==0,"shifted status scalar fields"); requireComplete(in, "status malformed or trailing data"); buffer.close();
    }
    {
        WsjtxMessage::DecodeFields f; f.time=QTime(12,34,56,789); f.snr=-12; f.deltaTime=.3; f.deltaFrequency=1234; f.mode="FT4"; f.message="CQ K1ABC FN42";
        auto packet=WsjtxMessage::decode("wfweb",f); readHeader(packet, &buffer, &in, &h); bool isNew,low,off; QTime time; qint32 snr; double dt; quint32 df; QByteArray mode,message;
        in>>isNew>>time>>snr>>dt>>df>>mode>>message>>low>>off;
        checkHeader(h,2); require(isNew&&time==f.time&&snr==-12&&dt==.3&&df==1234&&mode=="FT4"&&message=="CQ K1ABC FN42"&&!low&&!off,"bad decode fields"); requireComplete(in, "decode malformed or trailing data"); buffer.close();
    }
    {
        WsjtxMessage::QsoFields f; f.dateOff=QDateTime(QDate(2026,9,17),QTime(12,34,56),Qt::UTC); f.dateOn=f.dateOff.addSecs(-60); f.dxCall="K1ABC"; f.dxGrid="FN42"; f.txFrequency=14074000; f.mode="FT8"; f.reportSent="-08"; f.reportReceived="-11"; f.txPower="50"; f.comments="portable"; f.name="Alice"; f.operatorCall="N0CALL"; f.myCall="N0CALL"; f.myGrid="EM73"; f.exchangeSent="A"; f.exchangeReceived="B"; f.propagationMode="TR";
        auto packet=WsjtxMessage::qsoLogged("wfweb",f); readHeader(packet, &buffer, &in, &h); QDateTime off,on; QByteArray call,grid,mode,sent,received,power,comments,name,operatorCall,myCall,myGrid,exchangeSent,exchangeReceived,propagation; quint64 frequency;
        in>>off>>call>>grid>>frequency>>mode>>sent>>received>>power>>comments>>name>>on>>operatorCall>>myCall>>myGrid>>exchangeSent>>exchangeReceived>>propagation;
        checkHeader(h,5); require(off==f.dateOff&&on==f.dateOn,"schema-3 QDateTime mismatch"); require(call=="K1ABC"&&grid=="FN42"&&frequency==14074000&&mode=="FT8"&&sent=="-08"&&received=="-11","bad QSO core fields"); require(power=="50"&&comments=="portable"&&name=="Alice"&&operatorCall=="N0CALL"&&myCall=="N0CALL"&&myGrid=="EM73"&&exchangeSent=="A"&&exchangeReceived=="B"&&propagation=="TR","bad QSO text fields"); requireComplete(in, "QSO malformed or trailing data"); buffer.close();
    }
    {
        QByteArray adif("ADIF Export from wfweb\n<ADIF_VER:5>3.1.4 <PROGRAMID:5>wfweb <EOH>\n<CALL:5>K1ABC <MODE:3>FT8 <EOR>");
        auto packet=WsjtxMessage::loggedAdif("wfweb",adif); readHeader(packet, &buffer, &in, &h); QByteArray decoded; in>>decoded;
        checkHeader(h,12); require(decoded.startsWith("ADIF Export")&&decoded.contains("<EOH>")&&decoded.contains("<CALL:5>K1ABC")&&decoded.endsWith("<EOR>"),"bad complete Logged ADIF document"); requireComplete(in, "ADIF malformed or trailing data"); buffer.close();
    }
    {
        auto packet=WsjtxMessage::close("wfweb"); readHeader(packet, &buffer, &in, &h); checkHeader(h,6); requireComplete(in, "close malformed or trailing data"); buffer.close();
    }
    return 0;
}

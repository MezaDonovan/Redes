#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>
#include<stdbool.h>
#include <iostream>
#include <string>
#include <cstring>
#include <ws2tcpip.h>


using namespace std;

string recorridoPorBit(int comienzo,int terminacion,char datos[20]){
    char datosObtenidos[20];
    int posicion=0;
    for(int valor=comienzo;valor<terminacion;valor++){
        datosObtenidos[posicion] = datos[valor];
        posicion++;
    }
    return datosObtenidos;
}

void ipv6add(unsigned char *p){

    char addr[256];
    inet_ntop(AF_INET6,p,addr,sizeof (addr));
    printf("%s",addr);
}

void desgloseDeBits(char dato,int bitNumero){
    if(bitNumero == 3){
        cout<<"\n\t     Retardo: ";
        if(dato == '0'){
            cout<<"Normal";
        }else{
            cout<<"Bajo";
        }
    }else if(bitNumero == 4){
        cout<<"\n\t     Rendimiento: ";
        if(dato == '0'){
            cout<<"Normal";
        }else{
            cout<<"Alto";
        }
    }else if(bitNumero == 5){
        cout<<"\n\t     Fiabilidad: ";
        if(dato == '0'){
            cout<<"Normal";
        }else{
            cout<<"Alta";
        }
    }
}

int BinarioADecimal(long int dato){
    int digito=0,i=0,var=0;
    int vector[]={1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536};
    while(dato>0){
        digito = dato%10;
        if(digito==1){
            var=var+vector[i];
        }
        i++;
        dato=dato/10;
    }
    return var;
}

void flags(char dato,int bitNumero){
    if(bitNumero == 0){
        if(dato == '0'){
            cout<<"\n\t  Reservado";
        }
    }else if(bitNumero == 1){
        if(dato == '0'){
            cout<<"\n\t  Divisible";
        }else{
            cout<<"\n\t  No divisible(DF)";
        }
    }else if(bitNumero == 2){
        if(dato == '0'){
            cout<<"\n\t  Ultimo fragmento\n";
        }else{
            cout<<"\n\t  Fragmento Intermedio(le siguen mas fragmentos)(MF)\n";
        }
    }

}

string binario_8bits(char dato)
{
    char binario[12];
    for(int i=7;i>=0;i--){
        binario[i]=((dato & (1 << i)) ? '1' : '0');
    }
    strrev(binario);
    return binario;
}

void validacionDePrioridad(string lectura3Bits)
{
    if(lectura3Bits == "000"){
        cout<<"De rutina";
    }else if(lectura3Bits == "001"){
        cout<<"Prioritario";
    }else if(lectura3Bits == "010"){
        cout<<"Inmediato";
    }else if(lectura3Bits == "011"){
        cout<<"Relampago";
    }else if(lectura3Bits == "100"){
        cout<<"Invalidacion relampago";
    }else if(lectura3Bits == "101"){
        cout<<"Procesando llamada critica y de emergencia";
    }else if(lectura3Bits == "110"){
        cout<<"Control de trabajo de internet";
    }else if(lectura3Bits == "111"){
        cout<<"Control de red";
    }
}

char recorridoPorBitCaracter(int comienzo,int terminacion,char datos[20]){
    char datosObtenidos[20];
    int posicion=0;
    for(int valor=comienzo;valor<terminacion;valor++){
        datosObtenidos[posicion] = datos[valor];
        posicion++;
    }
    return datosObtenidos[0];
}
void protocolo(int decimal)
{
    switch(decimal)
    {
    case 0:
        cout<<"Hop-by-hope options";
        break;
    case 1:
        cout<<"ICMPv4";
        break;
    case 6:
        cout<<"TCP";
        break;
    case 17:
        cout<<"UDP";
        break;
    case 58:
        cout<<"ICMPv6";
        break;
    case 118:
        cout<<"STP";
        break;
    case 121:
        cout<<"SMP";
        break;
    }
}

int bin_decimal16Bits(int flag,char binario16Bits[16],int principio,int terminacion,bool mostrarBinario)
{
    char binarioResultante[16];
    int decimal=0;
    for(int i=principio;i<terminacion;i++){
        binarioResultante[i] = binario16Bits[i];
    }
    for(int i=terminacion-1;i>=principio;i--)
    {
        if(binarioResultante[i]=='1')
            decimal+=pow(2,i);
    }
    if(flag==1){
        cout<<"("<<decimal<<")"<<endl<<endl;
    }
    return decimal;

}

void typeICMPv4(int decimal){

    switch(decimal){
    case 0:
        cout<<"Echo Reply(respuesta de eco)";
        break;
    case 3:
        cout<<"Destination Unreacheable(destino inaccesible)";
        break;
    case 4:
        cout<<"Source Quench(disminucion del trafico desde el origen)";
        break;
    case 5:
        cout<<"Redirect(redireccionar - cambio de ruta)";
        break;
    case 8:
        cout<<"Echo(solicitud de eco)";
        break;
    case 11:
        cout<<"Time Exceeded(tiempo excedido para un datagrama)";
        break;
    case 12:
        cout<<"Parameter Problem(problema de parametros)";
        break;
    case 13:
        cout<<"Timestamp(solicitud de marca de tiempo)";
        break;
    case 14:
        cout<<"Timestamp Reply(respuesta de marca de tiempo)";
        break;
    case 15:
        cout<<"Information Request(solicitud de información)-obsoleto-";
        break;
    case 16:
        cout<<"Information Reply(respuesta de información)-obsoleto-";
        break;
    case 17:
        cout<<"Addressmask(solicitud de mascara de dirección)";
        break;
    case 18:
        cout<<"Addressmask Reply(respuesta de mascara de dirección)";
        break;
    }
}

void codeICMPv4(int decimal){

    switch(decimal){
    case 0:
        cout<<"No se puede llegar a la red";
        break;
    case 1:
        cout<<"No se puede llegar al host o aplicación de destino";
        break;
    case 2:
        cout<<"El destino no dispone del protocolo solicitado";
        break;
    case 3:
        cout<<"No se puede llegar al puerto destino o la aplicación destino no está libre";
        break;
    case 4:
        cout<<"Se necesita aplicar fragmentación, pero el flag correspondiente indica lo contrario";
        break;
    case 5:
        cout<<"La ruta de origen no es correcta";
        break;
    case 6:
        cout<<"No se conoce la red destino";
        break;
    case 7:
        cout<<"No se conoce el host destino";
        break;
    case 8:
        cout<<"El host origen esta aislado";
        break;
    case 9:
        cout<<"La comunicación con la red destino está prohibida por razones administrativas";
        break;
    case 10:
        cout<<"La comunicación con el host destino está prohibida por razones administrativas";
        break;
    case 11:
        cout<<"No se puede llegar a la red destino debido al Tipo de servicio";
        break;
    case 12:
        cout<<"No se puede llegar al host destino debido al Tipo de servicio ";
        break;
    }
}

void tipoDeHardware(int HDR)
{
    switch(HDR)
    {
    case 1:
        cout << "Ethernet (10mb)" << endl;
        break;
    case 6:
        cout << "IEEE 802 Networks" << endl;
        break;
    case 7:
        cout << "ARCNET" << endl;
        break;
    case 15:
        cout << "Frame Relay" << endl;
        break;
    case 16:
        cout << "Asynchronous Transfer Mode (ATM)" << endl;
        break;
    case 17:
        cout << "HDLC" << endl;
        break;
    case 18:
        cout << "Fibre Channel" << endl;
        break;
    case 19:
        cout << "Asynchronous Transfer Mode (ATM)" << endl;
        break;
    case 20:
        cout << "Serial Line" << endl;
        break;

    }
}

void CodigoOperacionARP(int decimal){
    switch(decimal){
    case 1:
        cout<<"ARP Request "<<endl;
        break;
    case 2:
        cout<<"ARP Reply  "<<endl;
        break;
    case 3:
        cout<<"RARP Request"<<endl;
        break;
    case 4:
        cout<<"RARP Reply "<<endl;
        break;
    }
}
void tipoDeProtocolo(int decimal){
    switch(decimal){
    case 2048:
        cout<<"0800 IPv4"<<endl;
        break;
    case 2054:
        cout<<"0806 ARP"<<endl;
        break;
    case 32821:
        cout<<"8035 RARP"<<endl;
        break;
    case 34525:
        cout<<"86DD IPv6"<<endl;
        break;
    }
}

int bin_decimal20Bits(int flag,char binario16Bits[20],int principio,int terminacion,bool mostrarBinario)
{
    char binarioResultante[20];
    int decimal=0;
    for(int i=principio;i<terminacion;i++){
        binarioResultante[i] = binario16Bits[i];
    }
    for(int i=terminacion-1;i>=principio;i--)
    {
        if(binarioResultante[i]=='1')
            decimal+=pow(2,i);
    }
    if(mostrarBinario == true)
    {
        for(int i=terminacion;i>=principio;i--){
         cout<<binarioResultante[i];
        }
    }
    if(flag==1){
        cout<<"("<<decimal<<")"<<endl<<endl;
    }
    return decimal;

}

void typeICMPv6_Y_CodeICMPv6(int tipo,int codigo){

    switch(tipo){
    case 1:
        cout<<"Mensaje de destino inalcanzable"<<endl;
        cout<<"\tCodigo: ";
        switch(codigo)
        {
            case 0:
                cout<<"No existe ruta destino";
                break;
            case 1:
                cout<<"Comunicacion con el destino administrativamente prohibida";
                break;
            case 2:
                cout<<"No asignado";
                break;
            case 3:
                cout<<"Direccion inalcanzable";
                break;
            }
        break;
    case 2:
        cout<<"Mensaje de paquete demasiado grande"<<endl;
        cout<<"\tCodigo: 0";
        break;
    case 3:
        cout<<"Time Exceeded Message"<<endl;
        cout<<"\tCodigo: ";
        switch(codigo)
        {
        case 0:
            cout<<"El limite del salto excedido";
            break;
        case 1:
            cout<<"Tiempo de reensamble de fragmento excedido";
            break;
        }
        break;
    case 4:
        cout<<"Mensaje de problema de parametro"<<endl;
        cout<<"\tCodigo: ";
        switch(codigo)
        {
        case 0:
            cout<<"El campo del encabezado erroneo encontro";
            break;
        case 1:
            cout<<"El tipo siguiente desconocido de la encabezado encontro";
            break;
        case 2:
            cout<<"Opcion desconocida del IPV6 encontrada";
            break;
        }
        break;
    case 128:
        cout<<"Mensaje del pedido de eco"<<endl;
        cout<<"\tCodigo: 0";
        break;
    case 129:
        cout<<"Mensaje de respuesta de eco"<<endl;
        cout<<"\tCodigo: 0";
        break;
    case 133:
        cout<<"Mensaje de solicitud del router"<<endl;
        cout<<"\tCodigo: 0";
        break;
    case 134:
        cout<<"Mensaje de anuncio del router"<<endl;
        cout<<"\tCodigo: 0";
        break;
    case 135:
        cout<<"Mensaje de solicitud vecino"<<endl;
        cout<<"\tCodigo: 0";
        break;
    case 136:
        cout<<"Mensaje de anuncio de vecino"<<endl;
        cout<<"\tCodigo: 0";
        break;
    case 137:
        cout<<"Redireccion de el mensaje"<<endl;
        cout<<"\tCodigo: 0";
        break;
    }
}

unsigned long int bin_decimal32Bits(int flag,char binario16Bits[32],int principio,int terminacion,bool mostrarBinario)
{
    char binarioResultante[32];
    unsigned long int decimal=0;
    for(int i=principio;i<terminacion;i++){
        binarioResultante[i] = binario16Bits[i];
    }
    for(int i=terminacion-1;i>=principio;i--)
    {
        if(binarioResultante[i]=='1')
            decimal+=pow(2,i);
    }
    if(mostrarBinario == true)
    {
        for(int i=terminacion;i>=principio;i--){
         cout<<binarioResultante[i];
        }
    }
    if(flag==1){
        cout<<"("<<decimal<<") BYTES"<<endl<<endl;
    }
    return decimal;

}

void flagsTCP(char dato,int bitNumero){
    if(bitNumero == 8){
        cout<<"\n\tNS (ECN-nonce concealment protection): ";
        if(dato == '0'){
            cout<<"Apagado";
        }else if(dato == '1'){
            cout<<"Encendido";
        }
    }else if(bitNumero == 0){
        cout<<"\n\tCWR (Congestion Window Reduced): ";
        if(dato == '0'){
            cout<<"Apagado";
        }else if(dato == '1'){
            cout<<"Encendido";
        }
    }else if(bitNumero == 1){
        cout<<"\n\tECE: ";
        if(dato == '0'){
            cout<<"Apagado";
        }else if(dato == '1'){
            cout<<"Encendido";
        }
    }else if(bitNumero == 2){
        cout<<"\n\tURG: ";
        if(dato == '0'){
            cout<<"Apagado";
        }else if(dato == '1'){
            cout<<"Encendido";
        }
    }else if(bitNumero == 3){
        cout<<"\n\tACK: ";
        if(dato == '0'){
            cout<<"Apagado";
        }else if(dato == '1'){
            cout<<"Encendido";
        }
    }else if(bitNumero == 4){
        cout<<"\n\tPSH(Push): ";
        if(dato == '0'){
            cout<<"Apagado";
        }else if(dato == '1'){
            cout<<"Encendido";
        }
    }else if(bitNumero == 5){
        cout<<"\n\tRST(Reset): ";
        if(dato == '0'){
            cout<<"Apagado";
        }else if(dato == '1'){
            cout<<"Encendido";
        }
    }else if(bitNumero == 6){
        cout<<"\n\tSYN(Synchronice): ";
        if(dato == '0'){
            cout<<"Apagado";
        }else if(dato == '1'){
            cout<<"Encendido";
        }
    }else if(bitNumero == 7){
        cout<<"\n\tFIN: ";
        if(dato == '0'){
            cout<<"Apagado";
        }else if(dato == '1'){
            cout<<"Encendido";
        }
    }
}

void tipoDePuerto(int temporal)
{
    if(temporal >= 0 && temporal <= 1023){
        cout<<"\tPuertos bien conocidos: "<<endl;
        switch(temporal)
        {
            case 20:
                cout<<"FTP"<<endl;
                break;
            case 21:
                cout<<"FTP"<<endl;
                break;
            case 22:
                cout<<"SSH"<<endl;
                break;
            case 23:
                cout<<"TELNET"<<endl;
                break;
            case 25:
                cout<<"SMTP"<<endl;
                break;
            case 53:
                cout<<"DNS"<<endl;
                break;
            case 67:
                cout<<"DHSP"<<endl;
                break;
            case 68:
                cout<<"DHSP"<<endl;
                break;
            case 69:
                cout<<"TFTP"<<endl;
                break;
            case 80:
                cout<<"HTTP"<<endl;
                break;
            case 110:
                cout<<"POP3"<<endl;
                break;
            case 143:
                cout<<"IMAP"<<endl;
                break;
            case 443:
                cout<<"HTTPS"<<endl;
                break;
            case 993:
                cout<<"IMAP SSL"<<endl;
                break;
            case 995:
                cout<<"POP SSL"<<endl;
                break;
            }
    }else if(temporal > 1023 && temporal <= 49151){
        cout<<"\tPuertos registrados"<<endl;
    }else if(temporal > 49151 && temporal <= 65535){
        cout<<"\tPuertos dinamicos o privados"<<endl;
    }
}

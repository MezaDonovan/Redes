#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>
#include<stdbool.h>
#include <iostream>
#include <string>
#include <cstring>
#include "Funciones.h"
using namespace std;

int main(){
    system("Title Analizador de Redes");
    int palabra;
    int byte[6];
    int i;
    string aux;
    char archi[100];
    int posfinal2=0;
    int total;
    int codeicmp4;
    string auxiliarCadenas1;
    string auxiliarCadenas2;
    char auxiliarChar1[20];
    char auxiliarChar2[20];
    char auxiliarChar3[20];
     char auxiliarChar4[20];
    long int ConversionInt = 0;
    bool mostrarBinario = false;
    char TemporalCharSinTamano;
    int temporal,auxiliar;
    int posicionBit =0;
    int contt=0;
    unsigned long int auxiliar32Bits = 0;



    FILE *archivo;

    printf("\tQue archivo deseas leer\t\n");
    cin>>archi;


    if ((archivo = fopen(archi,"rb+")) == NULL){
        printf ( " Error en la apertura. Es posible que el fichero no exista \n ");
    }
    else{
        fseek(archivo,0,SEEK_END);
        total=ftell(archivo);
        fseek(archivo,0,SEEK_SET);

        cout<<"\n---Cabecera Ethernet---\n\n";
        while (!feof(archivo)){
            if(ftell(archivo)==0){
                printf("Destination MAC Address:\n");
                for(i=0;i<=5;i++){
                    palabra=fgetc(archivo);
                    if(contt<5){
                                printf("%02x:",palabra);
                                contt++;
                            }
                            else{
                            printf("%02x",palabra);
                            }
                    byte[i]=palabra;
                    }
                    if(byte[0]==255 && byte[1]==255 && byte[2]==255 && byte[3]==255 && byte[4]==255 && byte[5]==255){
                                    printf("\n\tBrodcast");
                            }
                            else if((byte[0]&00000001)==00000000){
                                    printf("\n\tUnicast");
                            }
                            else if((byte[0]&00000001)==00000001){
                                    printf("\n\tMulticast");
                            }
                            if((byte[0]&00000010)==00000010){
                                printf ("\n\tlocally administered");
                            }
                            else if((byte[0]&00000010)==00000000){
                                printf("\n\tGlobally unique");
                            }
                             cin.ignore();
            }else if(ftell(archivo)==6){
                printf("\nSource MAC Address:\n");
                for(i=0;i<=5;i++){
                    palabra=fgetc(archivo);
                    printf ("%02x:",palabra);
                    byte[i]=palabra;
                    }
                    if(byte[0]==255 && byte[1]==255 && byte[2]==255 && byte[3]==255 && byte[4]==255 && byte[5]==255){
                                    printf("\n\tBrodcast");
                            }
                            else if((byte[0]&00000001)==00000000){
                                    printf("\n\tUnicast");
                            }
                            else if((byte[0]&00000001)==00000001){
                                    printf("\n\tMulticast");
                            }
                            if((byte[0]&00000010)==00000010){
                                printf ("\n\tlocally administered");
                            }
                            else if((byte[0]&00000010)==00000000){
                                printf("\n\tGlobally unique");
                            }
            }else if(ftell(archivo)==12){
                printf("\nEthertype:\n");
                for(i=0;i<=1;i++){
                    palabra=fgetc(archivo);
                    printf ("%02x",palabra);
                }

                fseek(archivo,12,SEEK_SET);
                palabra = fgetc(archivo);

                switch(palabra){
                case 8:
                    fseek(archivo,13,SEEK_SET);
                    palabra = fgetc(archivo);
                    if(palabra == 0){
                        cout<<"\tIPv4"<<endl;
                         int prueba=0;

                         fseek(archivo,14,SEEK_SET);
                         prueba = fgetc(archivo);
                         prueba=(prueba<<8)+fgetc(archivo);
                         cout<<prueba<<endl;
                         auxiliarCadenas2 = binario_8bits(palabra);
                         strcpy(auxiliarChar2,auxiliarCadenas2.c_str());
                         auxiliarCadenas1 = recorridoPorBit(0,4,auxiliarChar2); //recorre el arreglo segun la poscion/es deseada
                         if(auxiliarCadenas1 == "0100"){
                            cout<<endl<<"\t-------IPv4-------"<<endl<<endl;
                            cout<<"\tversion 4"<<endl;
                         }
                         auxiliarCadenas1 = recorridoPorBit(4,8,auxiliarChar2);
                         if(auxiliarCadenas1 == "0101"){
                            ConversionInt = stoi(auxiliarCadenas1);
                            cout<<"\tInternet Header Length(IHL)- "<<BinarioADecimal(ConversionInt)<<" ("<<(BinarioADecimal(ConversionInt)*32)/8<<"bytes)"<<endl;
                        }
                        fseek(archivo,15,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas2 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas2.c_str());
                        auxiliarCadenas1 = recorridoPorBit(0,3,auxiliarChar1);
                        cout<<endl<<"\t   Tipo de servicio";
                        cout<<endl<<"\t Prioridad: ";
                        validacionDePrioridad(auxiliarCadenas1);
                        cout<<endl<<"\t Caracteristicas del servicio"<<endl;
                        TemporalCharSinTamano = recorridoPorBitCaracter(3,4,auxiliarChar1);
                        posicionBit = 3;
                        desgloseDeBits(TemporalCharSinTamano,posicionBit);
                        TemporalCharSinTamano = recorridoPorBitCaracter(4,5,auxiliarChar1);
                        posicionBit = 4;
                        desgloseDeBits(TemporalCharSinTamano,posicionBit);
                        TemporalCharSinTamano = recorridoPorBitCaracter(5,6,auxiliarChar1);
                        posicionBit = 5;
                        desgloseDeBits(TemporalCharSinTamano,posicionBit);
                        TemporalCharSinTamano = recorridoPorBitCaracter(6,7,auxiliarChar1);
                        cout<<endl<<"\t     bits 6 - 7. Reservados para uso futuro"<<endl;

                        fseek(archivo,16,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas2 = binario_8bits(palabra);
                        strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                        fseek(archivo,17,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                        strcat(auxiliarChar2,auxiliarChar1);
                        strrev(auxiliarChar2);

                        cout<<endl<<"\tLongitud total:   Bytes";
                        mostrarBinario = false;
                        bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);

                        fseek(archivo,18,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas2 = binario_8bits(palabra);
                        strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                        fseek(archivo,19,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                        strcat(auxiliarChar2,auxiliarChar1);
                        strrev(auxiliarChar2);

                        cout<<endl<<"\tIdentificador:  ";
                        mostrarBinario = true;
                        bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);
                        cout<<endl<<"\tFlags";

                        fseek(archivo,20,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                        TemporalCharSinTamano = recorridoPorBitCaracter(0,1,auxiliarChar1);
                        posicionBit = 0;
                        flags(TemporalCharSinTamano,posicionBit);

                        TemporalCharSinTamano = recorridoPorBitCaracter(1,2,auxiliarChar1);
                        posicionBit = 1;
                        flags(TemporalCharSinTamano,posicionBit);

                        TemporalCharSinTamano = recorridoPorBitCaracter(2,3,auxiliarChar1);
                        posicionBit = 2;
                        flags(TemporalCharSinTamano,posicionBit);

                        fseek(archivo,21,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar2,auxiliarCadenas1.c_str());
                        strcat(auxiliarChar1,auxiliarChar2);

                        strrev(auxiliarChar1);
                        cout<<endl<<"\tPosicion de fragmento: ";
                        mostrarBinario = false;
                        bin_decimal16Bits(1,auxiliarChar1,0,13,mostrarBinario);

                        fseek(archivo,22,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                        ConversionInt = atoi(auxiliarChar1);
                        cout<<"\tTiempo de vida:  "<<BinarioADecimal(ConversionInt);

                        fseek(archivo,23,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                        ConversionInt = atoi(auxiliarChar1);
                        cout<<endl<<"\tProtocolo:  ";
                        protocolo(BinarioADecimal(ConversionInt));

                        cout<<endl<<"\tChecksum: 0x";
                        for(i=24;i<=25;i++){
                            palabra=fgetc(archivo);
                            printf ("%02x",palabra);

                        }

                        cout<<endl<<"\tDireccion ip de origen: ";
                        contt=0;
                        for(int i=26;i<=29;i++){
                            fseek(archivo,i,SEEK_SET);
                            palabra = fgetc(archivo);
                             if(contt<3){
                                printf("%d.",palabra);
                                contt++;
                            }
                            else{
                            printf("%d",palabra);
                            }
                        }
                        cout<<endl<<"\tDireccion ip de Destino: ";
                        contt=0;
                        for(int i=30;i<=33;i++){
                            fseek(archivo,i,SEEK_SET);
                            palabra = fgetc(archivo);
                             if(contt<3){
                                printf("%d.",palabra);
                                contt++;
                            }
                            else{
                            printf("%d",palabra);
                            }
                        }

                         cout<<endl<<endl<<"\t---------ICMPv4---------"<<endl;
                        fseek(archivo,34,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);

                        cout<<endl<<"\tType: ";
                        ConversionInt = stoi(auxiliarCadenas1);
                        temporal = BinarioADecimal(ConversionInt);
                        typeICMPv4(temporal);

                        fseek(archivo,35,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);

                        cout<<endl<<"\tCode: ";
                        ConversionInt = stoi(auxiliarCadenas1);
                        codeicmp4 = BinarioADecimal(ConversionInt);
                        codeICMPv4(codeicmp4);

                        cout<<endl<<"\tChecksum: 0x";
                        for(i=36;i<=37;i++){
                            palabra=fgetc(archivo);
                            printf ("%02x",palabra);
                        }

                        fseek(archivo,38,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas2 = binario_8bits(palabra);
                        strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                        fseek(archivo,39,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                        strcat(auxiliarChar2,auxiliarChar1);
                        strrev(auxiliarChar2);

                        if(temporal==0||temporal==8){
                        cout<<endl<<"\tIdentificador:  ";
                        mostrarBinario = true;
                        bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);

                        fseek(archivo,40,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas2 = binario_8bits(palabra);
                        strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                        fseek(archivo,41,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                        strcat(auxiliarChar2,auxiliarChar1);
                        strrev(auxiliarChar2);

                        cout<<"\tNumero de secuencia: ";
                        mostrarBinario = true;
                        bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);

                        fseek(archivo,34,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);

                        ConversionInt = stoi(auxiliarCadenas1);
                        temporal = BinarioADecimal(ConversionInt);
                        }

                        cout<<"\n\tDatos: ";

                        fseek(archivo,34,SEEK_SET);
                        for(i=0;i<total-42;i++){
                        posfinal2++;
                        }

                        cout<<posfinal2<<" bytes de carga util";

                        if(temporal==5){
                            cout<<endl<<"\n\tgateway a seguir:";
                            contt=0;
                            for(int i=26;i<=29;i++){
                                fseek(archivo,i,SEEK_SET);
                                palabra = fgetc(archivo);
                                if(contt<3){
                                    printf("%d.",palabra);
                                    contt++;
                                }
                                else{
                                cout<<"1"<<endl;
                                }
                            }
                        }

                        if(temporal==3||temporal==5||temporal==11){
                             fseek(archivo,42,SEEK_SET);
                             palabra = fgetc(archivo);

                             auxiliarCadenas2 = binario_8bits(palabra);
                             strcpy(auxiliarChar2,auxiliarCadenas2.c_str());
                             auxiliarCadenas1 = recorridoPorBit(0,4,auxiliarChar2); //recorre el arreglo segun la poscion/es deseada

                             if(auxiliarCadenas1 == "0100"){
                                cout<<endl<<"\t-------IPv4 (segunda vuelta)-------"<<endl<<endl;
                                cout<<"\tversion 4"<<endl;
                             }
                             auxiliarCadenas1 = recorridoPorBit(4,8,auxiliarChar2);
                             if(auxiliarCadenas1 == "0101"){
                                ConversionInt = stoi(auxiliarCadenas1);
                                cout<<"\tInternet Header Length(IHL)- "<<BinarioADecimal(ConversionInt)<<" ("<<(BinarioADecimal(ConversionInt)*32)/8<<"bytes)"<<endl;
                            }
                            fseek(archivo,43,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas2.c_str());
                            auxiliarCadenas1 = recorridoPorBit(0,3,auxiliarChar1);
                            cout<<endl<<"\t   Tipo de servicio";
                            cout<<endl<<"\t Prioridad: ";
                            validacionDePrioridad(auxiliarCadenas1);
                            cout<<endl<<"\t Caracteristicas del servicio"<<endl;
                            TemporalCharSinTamano = recorridoPorBitCaracter(3,4,auxiliarChar1);
                            posicionBit = 3;
                            desgloseDeBits(TemporalCharSinTamano,posicionBit);
                            TemporalCharSinTamano = recorridoPorBitCaracter(4,5,auxiliarChar1);
                            posicionBit = 4;
                            desgloseDeBits(TemporalCharSinTamano,posicionBit);
                            TemporalCharSinTamano = recorridoPorBitCaracter(5,6,auxiliarChar1);
                            posicionBit = 5;
                            desgloseDeBits(TemporalCharSinTamano,posicionBit);
                            TemporalCharSinTamano = recorridoPorBitCaracter(6,7,auxiliarChar1);
                            cout<<endl<<"\t     bits 6 - 7. Reservados para uso futuro"<<endl;

                            fseek(archivo,44,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                            fseek(archivo,45,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                            strcat(auxiliarChar2,auxiliarChar1);
                            strrev(auxiliarChar2);

                            cout<<endl<<"\tLongitud total:  Bytes";
                            mostrarBinario = false;
                            bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);

                            fseek(archivo,46,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                            fseek(archivo,47,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                            strcat(auxiliarChar2,auxiliarChar1);
                            strrev(auxiliarChar2);

                            cout<<endl<<"\tIdentificador:  ";
                            mostrarBinario = true;
                            bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);
                            cout<<endl<<"\tFlags";

                            fseek(archivo,48,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                            TemporalCharSinTamano = recorridoPorBitCaracter(0,1,auxiliarChar1);
                            posicionBit = 0;
                            flags(TemporalCharSinTamano,posicionBit);

                            TemporalCharSinTamano = recorridoPorBitCaracter(1,2,auxiliarChar1);
                            posicionBit = 1;
                            flags(TemporalCharSinTamano,posicionBit);

                            TemporalCharSinTamano = recorridoPorBitCaracter(2,3,auxiliarChar1);
                            posicionBit = 2;
                            flags(TemporalCharSinTamano,posicionBit);

                            fseek(archivo,49,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas1.c_str());
                            strcat(auxiliarChar1,auxiliarChar2);

                            strrev(auxiliarChar1);
                            cout<<endl<<"\tPosicion de fragmento: ";
                            mostrarBinario = false;
                            bin_decimal16Bits(1,auxiliarChar1,0,13,mostrarBinario);

                            fseek(archivo,50,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                            ConversionInt = atoi(auxiliarChar1);
                            cout<<"\tTiempo de vida:  "<<BinarioADecimal(ConversionInt);

                            fseek(archivo,51,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                            ConversionInt = atoi(auxiliarChar1);
                            cout<<endl<<"\tProtocolo:  ";
                            protocolo(BinarioADecimal(ConversionInt));

                            cout<<endl<<"\tChecksum: 0x";
                            for(i=52;i<=53;i++){
                                palabra=fgetc(archivo);
                                printf ("%02x",palabra);

                            }

                            cout<<endl<<"\tDireccion ip de origen: ";
                            contt=0;
                            for(int i=54;i<=57;i++){
                                fseek(archivo,i,SEEK_SET);
                                palabra = fgetc(archivo);
                                 if(contt<3){
                                    printf("%d.",palabra);
                                    contt++;
                                }
                                else{
                                printf("%d",palabra);
                                }
                            }
                            cout<<endl<<"\tDireccion ip de Destino: ";
                            contt=0;
                            for(int i=58;i<=61;i++){
                                fseek(archivo,i,SEEK_SET);
                                palabra = fgetc(archivo);
                                 if(contt<3){
                                    printf("%d.",palabra);
                                    contt++;
                                }
                                else{
                                printf("%d",palabra);
                                }
                            }
                        }

                    }else if(palabra == 6){
                        printf("\tARP\n");
                        cout<<"\tTipo de hardware: ";
                        fseek(archivo,14,SEEK_SET);
                        palabra = fgetc(archivo);
                        for(i=14;i<=15;i++){
                        palabra=fgetc(archivo);
                        if(palabra==1){
                            cout<<"Ethernet"<<endl;
                        }else if(palabra==0){
                            cout<<"Reserved"<<endl;
                        }
                        }
                        cout<<endl<<"\tTipo de protocolo: ";
                        fseek(archivo,15,SEEK_SET);
                        palabra = fgetc(archivo);
                        for(i=16;i<=17;i++){
                        palabra=fgetc(archivo);
                        printf("%02x",palabra);
                        }
                        fseek(archivo,16,SEEK_SET);
                        palabra = fgetc(archivo);
                        switch(palabra){
                            case 8:
                                fseek(archivo,17,SEEK_SET);
                                palabra = fgetc(archivo);
                                if(palabra == 0){
                                        cout<<"\tIPv4"<<endl;
                                    }else if(palabra == 6){
                                        printf("\tARP\n");
                                    }
                            break;
                            case 128:
                                fseek(archivo,17,SEEK_SET);
                                palabra = fgetc(archivo);
                                if(palabra == 53){
                                        printf("\tRARP");
                                    }
                            break;
                            case 134:
                                fseek(archivo,17,SEEK_SET);
                                palabra = fgetc(archivo);
                                if(palabra == 221){
                                        printf("\tIPv6");
                                    }
                            break;
                            }
                        cout<<endl<<"\tLongitud de la direccion hardware: ";
                        fseek(archivo,18,SEEK_SET);
                        palabra = fgetc(archivo);
                        printf("%i",palabra);

                        cout<<endl<<"\tLongitud de la direccion de protocolo: ";
                        fseek(archivo,19,SEEK_SET);
                        palabra = fgetc(archivo);
                        printf("%i",palabra);

                        cout<<endl<<"\tCodigo Operacion ARP: ";
                        fseek(archivo,19,SEEK_SET);
                        palabra = fgetc(archivo);
                        for(i=20;i<=21;i++){
                        palabra=fgetc(archivo);
                        printf("%02x",palabra);
                        }
                        fseek(archivo,21,SEEK_SET);
                        palabra = fgetc(archivo);
                        switch(palabra){
                            case 00: if(palabra==00){
                                cout<<"  (Reserved)"<<endl;
                            }
                            break;
                            case 01: if(palabra==01){
                                cout<<"  (Request)"<<endl;
                            }
                            break;
                            case 02: if(palabra==02){
                                cout<<"  (Reply)"<<endl;
                            }
                            break;
                        }

                        cout<<endl<<"\n\tDireccion MAC del emisor"<<endl<<"\t";
                        contt=0;
                        for(int i=22;i<=27;i++){
                            fseek(archivo,i,SEEK_SET);
                            palabra = fgetc(archivo);
                            if(contt<5){
                                printf("%02x:",palabra);
                                contt++;
                            }
                            else{
                            printf("%02x",palabra);
                            }
                        }
                        cout<<endl<<endl<<"\tDireccion IP del emisor"<<endl<<"\t";
                        contt=0;
                        for(int i=28;i<=31;i++){
                            fseek(archivo,i,SEEK_SET);
                            palabra = fgetc(archivo);
                            if(contt<3){
                                printf("%d.",palabra);
                                contt++;
                            }
                            else{
                            printf("%d",palabra);
                            }
                        }
                        cout<<endl<<endl<<"\tDireccion MAC del receptor"<<endl<<"\t";
                        contt=0;
                        for(int i=32;i<=37;i++){
                            fseek(archivo,i,SEEK_SET);
                            palabra = fgetc(archivo);
                            if(contt<5){
                                printf("%02x:",palabra);
                                contt++;
                            }
                            else{
                            printf("%02x",palabra);
                            }
                        }
                        cout<<endl<<endl<<"\tDireccion IP del receptor"<<endl<<"\t";
                        contt=0;
                        for(int i=38;i<=41;i++){
                            fseek(archivo,i,SEEK_SET);
                            palabra = fgetc(archivo);
                            if(contt<3){
                                printf("%d.",palabra);

                                contt++;
                            }
                            else{
                            printf("%d",palabra);
                            }
                        }
                    }
                 break;
                case 134:
                    fseek(archivo,13,SEEK_SET);
                    palabra = fgetc(archivo);
                    if(palabra == 221)
                    {
                        printf("\tIPv6\n");
                        fseek(archivo,14,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                        auxiliarCadenas2 = recorridoPorBit(0,4,auxiliarChar1); //recorre el arreglo segun la poscion/es deseada
                        if(auxiliarCadenas2 == "0110"){
                            cout<<endl<<"\t---------IPv6---------"<<endl<<endl;
                            cout<<"\tVersion 6"<<endl;
                        }
                        auxiliarCadenas1 = recorridoPorBit(4,8,auxiliarChar1);
                        fseek(archivo,15,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas2 = binario_8bits(palabra);
                        strcpy(auxiliarChar2,auxiliarCadenas2.c_str());
                        auxiliarCadenas2 = recorridoPorBit(0,4,auxiliarChar2);

                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                        strcpy(auxiliarChar2,auxiliarCadenas2.c_str());
                        strcat(auxiliarChar1,auxiliarChar2);
                        strrev(auxiliarChar1);

                        cout<<"\n\tClase de trafico: "<<endl;
                        auxiliarCadenas1 = recorridoPorBit(0,3,auxiliarChar1);

                        cout<<endl<<"\t   Tipo de servicio";
                        cout<<endl<<"\t Prioridad: ";
                        validacionDePrioridad(auxiliarCadenas1);
                        cout<<endl<<"\t Caracteristicas del servicio"<<endl;
                        TemporalCharSinTamano = recorridoPorBitCaracter(3,4,auxiliarChar1);
                        posicionBit = 3;
                        desgloseDeBits(TemporalCharSinTamano,posicionBit);
                        TemporalCharSinTamano = recorridoPorBitCaracter(4,5,auxiliarChar1);
                        posicionBit = 4;
                        desgloseDeBits(TemporalCharSinTamano,posicionBit);
                        TemporalCharSinTamano = recorridoPorBitCaracter(5,6,auxiliarChar1);
                        posicionBit = 5;
                        desgloseDeBits(TemporalCharSinTamano,posicionBit);
                        TemporalCharSinTamano = recorridoPorBitCaracter(6,7,auxiliarChar1);
                        cout<<endl<<"\t     bits 6 - 7. Reservados para uso futuro"<<endl;


                        auxiliarCadenas2 = recorridoPorBit(4,8,auxiliarChar2);

                        fseek(archivo,16,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                        fseek(archivo,17,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar3,auxiliarCadenas1.c_str());

                        strcat(auxiliarChar2,auxiliarChar1);
                        strcat(auxiliarChar2,auxiliarChar3);
                        strrev(auxiliarChar2);

                        mostrarBinario = false;
                        cout<<endl<<"\t Etiqueta de flujo: ";
                        bin_decimal20Bits(1,auxiliarChar2,0,20,mostrarBinario);

                        fseek(archivo,18,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                        fseek(archivo,19,SEEK_SET);

                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar2,auxiliarCadenas1.c_str());
                        strcat(auxiliarChar1,auxiliarChar2);
                        strrev(auxiliarChar1);
                        mostrarBinario = false;

                        cout<<endl<<"\tTamano de datos: Bytes ";
                        bin_decimal16Bits(1,auxiliarChar1,0,16,mostrarBinario);

                        fseek(archivo,20,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                        ConversionInt = atoi(auxiliarChar1);
                        cout<<endl<<"\tNext header:  ";
                        protocolo(BinarioADecimal(ConversionInt));


                        fseek(archivo,21,SEEK_SET);
                        palabra = fgetc(archivo);
                        printf("\n\tlimite de saltos: %d",palabra);

                        cout<<endl<<endl<<"\tDireccion de origen"<<endl<<"\t";
                        unsigned char memoria[20];
                        fseek (archivo, 22, SEEK_SET);
                        fread (memoria,1,16,archivo);
                        ipv6add (memoria);
                        cout<<endl<<endl<<"\tDireccion de destino"<<endl<<"\t";
                        fseek (archivo, 38, SEEK_SET);
                        fread (memoria,1,16,archivo);
                        ipv6add (memoria);


                        fseek(archivo,54,SEEK_SET);
                        palabra = fgetc(archivo);

                        while(palabra==0x3a){
                        cout<<"\n\n\t--Extra header--"<<endl;
                        cout<<"\tHeader: Hop-by-hope"<<endl;
                        int s=true;

                        fseek(archivo,54,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                        ConversionInt = atoi(auxiliarChar1);
                        cout<<"\tNetx Header: ";
                        protocolo(BinarioADecimal(ConversionInt));

                        cout<<endl<<"\tHeader extension lenght: ";
                        fseek(archivo,55,SEEK_SET);
                        palabra = fgetc(archivo);
                        palabra+=1;
                        palabra*=8;
                        cout<<palabra;

                        cout<<endl<<"\tpay load:";
                        palabra-=2;
                        cout<<palabra;

                         cout<<endl<<endl<<"\t---------PROTOCOLO ";
                         cout<<"ICMPv6---------";
                        fseek(archivo,54,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);

                        cout<<endl<<"\tType: ";
                        if (s==true){
                            printf("143");
                        }
                        ConversionInt = stoi(auxiliarCadenas1);
                        temporal = BinarioADecimal(ConversionInt);

                        fseek(archivo,63,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        ConversionInt = stoi(auxiliarCadenas1);
                        auxiliar = BinarioADecimal(ConversionInt);

                        typeICMPv6_Y_CodeICMPv6(temporal,auxiliar);

                        cout<<endl<<"\tChecksum: 0x";
                        for(i=56;i<=57;i++){
                            palabra=fgetc(archivo);
                            printf ("%02x",palabra);
                            }
                        }


                        fseek(archivo,20,SEEK_SET);
                        palabra = fgetc(archivo);
                        auxiliarCadenas1 = binario_8bits(palabra);
                        strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                        ConversionInt = atoi(auxiliarChar1);
                        temporal = BinarioADecimal(ConversionInt);
                        switch(temporal)
                        {
                        case 6:
                            cout<<endl<<endl<<"\t---------PROTOCOLO ";
                            cout<<"TCP---------"<<endl;

                            cout<<endl<<"\tPuerto de Origen: ";
                            fseek(archivo,54,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                            fseek(archivo,55,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                            strcat(auxiliarChar2,auxiliarChar1);
                            strrev(auxiliarChar2);
                            mostrarBinario = false;
                            temporal = bin_decimal16Bits(0,auxiliarChar2,0,16,mostrarBinario);
                            cout<<temporal<<endl;

                            tipoDePuerto(temporal);

                            cout<<endl<<"\tPuerto de Destino: ";
                            fseek(archivo,56,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                            fseek(archivo,57,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                            strcat(auxiliarChar2,auxiliarChar1);
                            strrev(auxiliarChar2);
                            mostrarBinario = false;
                            temporal = bin_decimal16Bits(0,auxiliarChar2,0,16,mostrarBinario);
                            cout<<temporal<<endl;

                            tipoDePuerto(temporal);

                            cout<<endl<<"\tNumero de secuencia: ";
                            fseek(archivo,58,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                            fseek(archivo,59,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());
                            strcat(auxiliarChar1,auxiliarChar2);

                            fseek(archivo,60,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar3,auxiliarCadenas1.c_str());


                            fseek(archivo,61,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar4,auxiliarCadenas2.c_str());
                            strcat(auxiliarChar3,auxiliarChar4);
                            strcat(auxiliarChar1,auxiliarChar3);
                            strrev(auxiliarChar1);
                            mostrarBinario = false;

                            auxiliar32Bits = bin_decimal32Bits(0,auxiliarChar1,0,32,mostrarBinario);
                            cout<<auxiliar32Bits<<endl;

                            cout<<"\tNumero de acuse de recibo: ";
                            fseek(archivo,62,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                            fseek(archivo,63,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());
                            strcat(auxiliarChar1,auxiliarChar2);

                            fseek(archivo,64,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar3,auxiliarCadenas1.c_str());

                            fseek(archivo,65,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar4,auxiliarCadenas2.c_str());
                            strcat(auxiliarChar3,auxiliarChar4);
                            strcat(auxiliarChar1,auxiliarChar3);
                            strrev(auxiliarChar1);
                            mostrarBinario = false;

                            auxiliar32Bits = bin_decimal32Bits(0,auxiliarChar1,0,32,mostrarBinario);
                            cout<<auxiliar32Bits<<endl;

                            cout<<"\tLongitud de cabecera: ";
                            fseek(archivo,66,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                            auxiliarCadenas2 = recorridoPorBit(0,4,auxiliarChar1);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());
                            ConversionInt = atoi(auxiliarChar2);
                            temporal = BinarioADecimal(ConversionInt);
                            cout<<temporal<<endl;

                            cout<<"\tReservado: ";
                            auxiliarCadenas2 = recorridoPorBit(4,7,auxiliarChar1);
                            TemporalCharSinTamano = recorridoPorBitCaracter(4,5,auxiliarChar1);
                            cout<<" "<<TemporalCharSinTamano;
                            TemporalCharSinTamano = recorridoPorBitCaracter(5,6,auxiliarChar1);
                            cout<<" "<<TemporalCharSinTamano;
                            TemporalCharSinTamano = recorridoPorBitCaracter(6,7,auxiliarChar1);
                            cout<<" "<<TemporalCharSinTamano;

                            cout<<endl<<"\tbits 4 - 6. Reservados para uso futuro"<<endl;
                            cout<<endl<<"\tFlags";

                            TemporalCharSinTamano = recorridoPorBitCaracter(7,8,auxiliarChar1);
                            posicionBit = 8;
                            flagsTCP(TemporalCharSinTamano,posicionBit);

                            fseek(archivo,67,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                            TemporalCharSinTamano = recorridoPorBitCaracter(0,1,auxiliarChar2);
                            posicionBit = 0;
                            flagsTCP(TemporalCharSinTamano,posicionBit);

                            TemporalCharSinTamano = recorridoPorBitCaracter(1,2,auxiliarChar2);
                            posicionBit = 1;
                            flagsTCP(TemporalCharSinTamano,posicionBit);

                            TemporalCharSinTamano = recorridoPorBitCaracter(2,3,auxiliarChar2);
                            posicionBit = 2;
                            flagsTCP(TemporalCharSinTamano,posicionBit);

                            TemporalCharSinTamano = recorridoPorBitCaracter(3,4,auxiliarChar2);
                            posicionBit = 3;
                            flagsTCP(TemporalCharSinTamano,posicionBit);

                            TemporalCharSinTamano = recorridoPorBitCaracter(4,5,auxiliarChar2);
                            posicionBit = 4;
                            flagsTCP(TemporalCharSinTamano,posicionBit);

                            TemporalCharSinTamano = recorridoPorBitCaracter(5,6,auxiliarChar2);
                            posicionBit = 5;
                            flagsTCP(TemporalCharSinTamano,posicionBit);

                            TemporalCharSinTamano = recorridoPorBitCaracter(6,7,auxiliarChar2);
                            posicionBit = 6;
                            flagsTCP(TemporalCharSinTamano,posicionBit);

                            TemporalCharSinTamano = recorridoPorBitCaracter(7,8,auxiliarChar2);
                            posicionBit = 7;
                            flagsTCP(TemporalCharSinTamano,posicionBit);

                            cout<<endl<<endl<<"\tTamaño de ventana: ";
                            fseek(archivo,68,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                            fseek(archivo,69,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());
                            strcat(auxiliarChar1,auxiliarChar2);
                            strrev(auxiliarChar1);
                            mostrarBinario = false;

                            cout<<bin_decimal16Bits(0,auxiliarChar1,0,16,mostrarBinario);

                            cout<<endl<<"\tChecksum: 0x";
                            for(i=70;i<=71;i++){
                                palabra=fgetc(archivo);
                                printf ("%02x",palabra);

                            }
                            cout<<endl;
                            cout<<"\tPuerto Urgente: ";
                            fseek(archivo,72,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());

                            fseek(archivo,73,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());
                            strcat(auxiliarChar1,auxiliarChar2);
                            strrev(auxiliarChar1);
                            mostrarBinario = false;
                            cout<<bin_decimal16Bits(0,auxiliarChar1,0,16,mostrarBinario);
                            break;
                        case 17:
                            cout<<endl<<endl<<"\t---------PROTOCOLO ";
                            cout<<"UDP---------\n";

                            cout<<endl<<"\tPuerto de Origen: ";

                            fseek(archivo,54,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                            fseek(archivo,55,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                            strcat(auxiliarChar2,auxiliarChar1);
                            strrev(auxiliarChar2);
                            mostrarBinario = false;
                            temporal = bin_decimal16Bits(0,auxiliarChar2,0,16,mostrarBinario);

                            cout<<temporal<<endl;

                            tipoDePuerto(temporal);

                            cout<<endl<<"\tPuerto de Destino: ";
                            fseek(archivo,56,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                            fseek(archivo,57,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                            strcat(auxiliarChar2,auxiliarChar1);
                            strrev(auxiliarChar2);
                            mostrarBinario = false;
                            temporal = bin_decimal16Bits(0,auxiliarChar2,0,16,mostrarBinario);
                            cout<<temporal<<endl;

                            tipoDePuerto(temporal);

                            fseek(archivo,58,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas2 = binario_8bits(palabra);
                            strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                            fseek(archivo,59,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                            strcat(auxiliarChar2,auxiliarChar1);
                            strrev(auxiliarChar2);

                            cout<<endl<<"\tLongitud total:  ";
                            mostrarBinario = false;
                            bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);

                            cout<<"\tChecksum: 0x";
                            for(i=60;i<=61;i++){
                                palabra=fgetc(archivo);
                                printf ("%02x",palabra);

                            }

                            break;
                        case 53:
                            cout<<endl<<endl<<"\t---------PROTOCOLO ";
                            cout<<"DNS---------";
                            break;
                        case 58:
                            cout<<endl<<endl<<"\t---------PROTOCOLO ";
                            cout<<"ICMPv6---------";
                            fseek(archivo,54,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);

                            cout<<endl<<"\tType: ";
                            ConversionInt = stoi(auxiliarCadenas1);
                            temporal = BinarioADecimal(ConversionInt);

                            fseek(archivo,55,SEEK_SET);
                            palabra = fgetc(archivo);
                            auxiliarCadenas1 = binario_8bits(palabra);
                            ConversionInt = stoi(auxiliarCadenas1);
                            auxiliar = BinarioADecimal(ConversionInt);

                            typeICMPv6_Y_CodeICMPv6(temporal,auxiliar);

                            cout<<endl<<"\tChecksum: 0x";
                            for(i=56;i<=57;i++){
                                palabra=fgetc(archivo);
                                printf ("%02x",palabra);
                            }
                            cout<<endl;

                            switch(temporal){
                            case 128:
                                cout<<"\t---ICMP pedido de eco"<<endl;
                                fseek(archivo,58,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas2 = binario_8bits(palabra);
                                strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                                fseek(archivo,59,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas1 = binario_8bits(palabra);
                                strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                                strcat(auxiliarChar2,auxiliarChar1);
                                strrev(auxiliarChar2);

                                cout<<endl<<"\tIdentificador:  ";
                                mostrarBinario = true;
                                bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);

                                fseek(archivo,60,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas2 = binario_8bits(palabra);
                                strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                                fseek(archivo,61,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas1 = binario_8bits(palabra);
                                strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                                strcat(auxiliarChar2,auxiliarChar1);
                                strrev(auxiliarChar2);

                                cout<<"\tNumero de secuencia: ";
                                mostrarBinario = true;
                                bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);

                                fseek(archivo,54,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas1 = binario_8bits(palabra);

                                ConversionInt = stoi(auxiliarCadenas1);
                                temporal = BinarioADecimal(ConversionInt);

                                cout<<"\tDatos: ";
                                posfinal2=0;
                                for(i=0;i<total-62;i++){
                                posfinal2++;
                                }

                                cout<<posfinal2<<" bytes de carga util";
                                break;
                            case 129:
                                cout<<"\t---ICMP respuesta de eco"<<endl;
                                fseek(archivo,58,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas2 = binario_8bits(palabra);
                                strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                                fseek(archivo,59,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas1 = binario_8bits(palabra);
                                strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                                strcat(auxiliarChar2,auxiliarChar1);
                                strrev(auxiliarChar2);

                                cout<<endl<<"\tIdentificador:  ";
                                mostrarBinario = true;
                                bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);

                                fseek(archivo,60,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas2 = binario_8bits(palabra);
                                strcpy(auxiliarChar2,auxiliarCadenas2.c_str());

                                fseek(archivo,61,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas1 = binario_8bits(palabra);
                                strcpy(auxiliarChar1,auxiliarCadenas1.c_str());
                                strcat(auxiliarChar2,auxiliarChar1);
                                strrev(auxiliarChar2);

                                cout<<"\tNumero de secuencia: ";
                                mostrarBinario = true;
                                bin_decimal16Bits(1,auxiliarChar2,0,16,mostrarBinario);

                                fseek(archivo,54,SEEK_SET);
                                palabra = fgetc(archivo);
                                auxiliarCadenas1 = binario_8bits(palabra);

                                ConversionInt = stoi(auxiliarCadenas1);
                                temporal = BinarioADecimal(ConversionInt);

                                cout<<"\tDatos: ";
                                posfinal2=0;
                                for(i=0;i<total-62;i++){
                                posfinal2++;
                                }

                                cout<<posfinal2<<" bytes de carga util";
                                break;
                            case 133:
                                cout<<"\n\t---ICMP solicitud del router"<<endl;
                                cout<<"\t---ICMP option"<<endl;
                                cout<<"\tType: source link Layer Address"<<endl;
                                cout<<"\toption Length: 8 Bytes "<<endl;
                                cout<<"\tLink Layer Address: ";
                                contt=0;
                                fseek(archivo,64,SEEK_SET);
                                for(i=0;i<=5;i++){
                                    palabra=fgetc(archivo);
                                        if(contt<5){
                                            printf("%02x:",palabra);
                                            contt++;
                                        }
                                        else{
                                        printf("%02x",palabra);
                                        }
                                }
                                break;
                            case 134:
                                cout<<"\n\t---ICMP anuncio del router"<<endl;
                                cout<<"\tcur hop limit: 64"<<endl;
                                cout<<"\tManaged address configuration: 0"<<endl;
                                cout<<"\tOther configuration: 0"<<endl;
                                cout<<"\tRouter life time: 30"<<endl;
                                cout<<"\tReacheable time: 0"<<endl;
                                cout<<"\tRetrans timer: 0"<<endl;
                                cout<<"\t---ICMP option"<<endl;
                                cout<<"\n\tType: Prefix information"<<endl;
                                cout<<"\n\tOption length: 32 Bytes"<<endl;
                                cout<<"\n\t-Prefix length: 64 bits"<<endl;
                                cout<<"\n\t-Link flag: 1"<<endl;
                                cout<<"\n\tAutonomus address-configuration flag: 1"<<endl;
                                cout<<"\n\tvalid life time: 0x000015180"<<endl;
                                cout<<"\n\tPreferred lifetime: 0x00003840"<<endl;
                                cout<<"\n\tPrefix: ";
                                fseek (archivo, 84, SEEK_SET);
                                fread (memoria,1,16,archivo);
                                ipv6add (memoria);
                                cout<<"\n\tType: source link Layer Address"<<endl;
                                cout<<"\toption Length: 8 Bytes "<<endl;
                                cout<<"\tLink Layer Address: ";
                                contt=0;
                                fseek(archivo,104,SEEK_SET);
                                for(i=0;i<=5;i++){
                                    palabra=fgetc(archivo);
                                        if(contt<5){
                                            printf("%02x:",palabra);
                                            contt++;
                                        }
                                        else{
                                        printf("%02x",palabra);
                                        }
                                }
                                break;
                            case 135:
                                cout<<"\t---ICMP solicitud vecino"<<endl;
                                cout<<"\tTarget Address: ";
                                fseek (archivo, 22, SEEK_SET);
                                fread (memoria,1,16,archivo);
                                ipv6add (memoria);
                                cout<<endl<<"\t---ICMP option"<<endl;
                                cout<<"\tType: Target link Layer Address"<<endl;
                                cout<<"\tLink Layer Address: ";
                                contt=0;
                                fseek(archivo,80,SEEK_SET);
                                for(i=0;i<=5;i++){
                                    palabra=fgetc(archivo);
                                        if(contt<5){
                                            printf("%02x:",palabra);
                                            contt++;
                                        }
                                        else{
                                        printf("%02x",palabra);
                                        }
                                }
                                break;
                            case 136:
                                cout<<"\t---ICMP anuncio de vecino"<<endl;
                                cout<<"\tTarget Address: ";
                                fseek (archivo, 22, SEEK_SET);
                                fread (memoria,1,16,archivo);
                                ipv6add (memoria);
                                cout<<endl<<"\t---ICMP option"<<endl;
                                cout<<"\tType: Target link Layer Address"<<endl;
                                cout<<"\tLink Layer Address: ";
                                contt=0;
                                fseek(archivo,80,SEEK_SET);
                                for(i=0;i<=5;i++){
                                    palabra=fgetc(archivo);
                                        if(contt<5){
                                            printf("%02x:",palabra);
                                            contt++;
                                        }
                                        else{
                                        printf("%02x",palabra);
                                        }
                                }
                                break;
                            case 137:
                                cout<<"\t---ICMP Redireccion de el mensaje"<<endl;
                                break;
                            }

                            break;
                        }

                    }
                    break;
                }
            }
        }
    }
}

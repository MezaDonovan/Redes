
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <math.h>
#include <pcap.h>

#define LINE_LEN 16

int menu(int array[],int tamanio);
int binario_decimal(int array[], int y);
void ipv4(int numeros[]);
void funcion_ipv4_tcp(int x);
void arp_rarp(int numeros[]);
void IPV6(int numeros[]);
int DNS=0;
int QDcount=0,ANcount=0,NScount=0,ARcount=0;

int main(int argc, char **argv){
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
	printf("   Usage: pktdump_ex [-s source]\n\n"
		"   Examples:\n"
		"      pktdump_ex -s file.acp\n"
		"      pktdump_ex -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

	if(argc < 3){
		printf("\nNo se ha seleccionado ning�n adaptador: impresi�n de la lista de dispositivos:\n");
		if(pcap_findalldevs(&alldevs, errbuf) == -1){
			fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
			exit(1);
		}
		for(d=alldevs; d; d=d->next){
			printf("%d. %s\n    ", ++i, d->name);

			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No hay descripci�n disponible)\n");
		}
		if (i==0){
			printf("\nNo se han encontrado interfaces. Aseg�rese de que WinPcap est� instalado.\n");
			return -1;
		}
		printf("Ingrese el numero de interfaz: (1-%d):",i);
		scanf("%d", &inum);
		if (inum < 1 || inum > i){
			printf("\nInterfaz fuera de rango.\n");
			pcap_freealldevs(alldevs);
			return -1;
		}
		for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
		if ((fp = pcap_open_live(d->name,65536,1,1000,errbuf)) == NULL){
			fprintf(stderr,"\nError al abrir el adaptador\n");
			return -1;
		}
	}
	else{
		if ((fp = pcap_open_live(argv[2],65536,1,1000,errbuf)) == NULL){
			fprintf(stderr,"\nError al abrir el adaptador\n");
			return -1;
		}

	}
/*************************************************************************************************************/
	int control=0;
	int tamanio;

    while( ((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0) && control < 500 ){
		if(res == 0)
			continue;

		int tamanio=header->len;
		printf("***********************************************************************************");
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, tamanio);
        int array[tamanio];
		for (i=1; (i < header->caplen + 1 ) ; i++){
			array[i-1]=pkt_data[i-1];
		}

		printf("\n\n");
        menu(array,tamanio);
		control++;
	}


	//*********************************************************************************************
	if(res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	pcap_close(fp);

	return 0;
}


int menu(int array[],int tamanio){
    unsigned char car =0;
    unsigned char tipo[4];
    int numeros[(tamanio-14)*8];
    int octeto[8];
    int cont=0,cont2=0,var=0;
    printf("TAMANIO: %i\n",tamanio);

    printf("++++++++++++++++++++++++ENCABEZADO ETHERNET++++++++++++++++++++++++\n");
    printf("Direccion Destino: ");

    for(int cont=0;cont<tamanio;cont++){

        if(cont==6){printf("\nDireccion Origen: ");}
        if(cont==12){printf("\nTipo: ");}
        if(cont==12){
            for (int i=0;i<1;i++){
                tipo[i]=array[cont];
            }
        }
        if(cont==13){
            for(int i=1;i<2;i++){
                tipo[i]=array[cont];
            }
        }
        if (cont<14){
            printf("%02X ",array[cont]);
        }



        if (cont>=14 && cont < tamanio){
            car=array[cont];
            int x=0;
            while(car>0){//convertidor a binario
                octeto[x]=car%2;
                car=car/2;
                x++;
            }
            cont2 = x;
            int cont3=0;

            do{//Guardamos el numero en nuestro arreglo
                if(cont2 !=8){
                    int aux=0;
                    numeros[var]=aux;
                    cont2++;
                    cont3++;
                    var++;
                }else{
                    for(int y=x-1; y>=0; y--){
                        int aux=octeto[y];
                        numeros[var]=aux;
                        cont3++;
                        var++;
                    }
                }
            }while(cont3!=8);



        }

    }
        cont=0;
        if (tipo[0]==0x08&&tipo[1]==0x00){
            printf(" (IPv4)\n");
            printf("*******************ENCABEZADO IPV4*******************\n");
            ipv4(numeros);
        }printf("\n");

        if (tipo[0]==0x08&&tipo[1]==0x06){
            printf("(ARP)\n");
            printf("*******************ARP*******************\n");
            arp_rarp(numeros);
        }

        if (tipo[0]==0x80&&tipo[1]==0x35){
            printf("(RARP)\n");
            printf("*******************RARP*******************\n");
            arp_rarp(numeros);
        }
        if (tipo[0]==0x86&&tipo[1]==0xDD){
            printf("(IPv6)\n");
            printf("*******************IPV6*******************\n");
            IPV6(numeros);
        }
    system("pause");
    return (0);
}




void IPV6(int numeros[]){
    int cont=0,y=0, band=1, band2=0, suenio=0;
    int array[32];
    printf("\nVersion: ");
    int i=0;
    while(i<500){
        if(i<4){
            array[y]=numeros[cont];
            y++;
        }
        if(i==4){
            printf("%d",binario_decimal(array,4));
            y=0;
            printf("\nClase de trafico: ");
        }

        if(i>=4 && i<=6){
            array[y]=numeros[cont];
            y++;
        }
        if(i==7){
            printf("\n\tDesglose de bits: ");
            switch(binario_decimal(array,y)){
                case 0: printf("(De rutina)");break;
                case 1: printf("(Prioritari)");break;
                case 2: printf("(Inmediato)");break;
                case 3: printf("(Relampago)");break;
                case 4: printf("(Invalidacion relampago)");break;
                case 5: printf("(Procesando llamada critica y de emergencia)");break;
                case 6: printf("(Control de trabajo de internet)");break;
                case 7: printf("(Control de red)");break;
            }
            y=0;
        }
        if(i==7){
            if(numeros[cont]==0){
                printf("\n\tRetardo: Normal ");
            }else{printf("\tRetardo: Bajo ");
                }
        }
        if(i==8){
            if(numeros[cont]==0){
                printf("\n\tRendimiento: Normal ");
            }else{printf("\n\tRendimiento: Alto ");
                }
        }
        if(i==9){
            if(numeros[cont]==0){
                printf("\n\tFiabilidad: Normal ");
            }else{printf("\n\tFiabilidad: Alto ");
                }
        }
        if(i==10){printf("\n\tBits reservados: ");}
        if(i>=10 && i<=11){
            printf("%d",numeros[cont]);
        }


        if(i==12){
            printf("\nEtiqueta de flujo: ");
        }
        if(i>=12 && i<=31){
            array[y]=numeros[cont];
            y++;
        }
        if(i==32){
            printf("%d",binario_decimal(array,20));
            y=0;
        }
        if(i==32){
            printf("\nTamanio de datos: ");
            while(band <= 2){
                for(int k = 0 ; k < 8 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("%d ",binario_decimal(array,8));
                band++;
            }
            band=1;
        }
        if(i==48){
            printf("\nEncabezado siguiente: ");
        }
        if(i>=48 && i<=55){
            array[y]=numeros[cont];
            y++;
        }

        if(i==56){
            switch(binario_decimal(array,8)){
                case 1: printf("ICMP v4\n"); suenio=1;break;
                case 6: printf("TCP\n");suenio=2;break;
                case 17: printf("UDP\n");suenio=3;break;
                case 58: printf("ICMPv6\n");suenio=4;break;
                case 118: printf("STP\n");suenio=5;break;
                case 121: printf("SMP\n");suenio=6;break;
            }
            y=0;
            printf("Limite de salto: ");
        }
        if(i>=56 && i<=63){
            array[y]=numeros[cont];
            y++;
        }
        if(i==64){
            printf("%d",binario_decimal(array,8));
            y=0;
        }
        if(i==64){
            printf("\nDireccion de origen: ");
            while(band <= 8){
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                if(band !=8){
                    printf("%04X:",binario_decimal(array,16));
                }else{
                    printf("%04X",binario_decimal(array,16));
                }
                band++;
            }
            band=1;
        }
        if(i==192){
            printf("\nDireccion de destino: ");
            while(band <= 8){
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                if(band !=8){
                    printf("%04X:",binario_decimal(array,16));
                }else{
                    printf("%04X",binario_decimal(array,16));
                }
                band++;
            }
            band=1;
            printf("\nTipo: ");
        }
        if(i>=320 && i<=327){
            array[y]=numeros[cont];
            y++;
        }
        if(i==328){
            switch(binario_decimal(array,8)){
                case 1:
                    printf("Mensaje de destino inalcanzable\n");
                    for(int k=0 ; k<8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    switch(binario_decimal(array,8)){
                        case 0:
                            printf("\tNo existe ruta de destino");
                        break;
                        case 1:
                            printf("\tComunicacion con el destino administrativamente prohibida");
                        break;
                        case 2:
                            printf("\tNo asignado");
                        break;
                        case 3:
                            printf("\tDireccion inalcanzable\n");
                        break;
                    }
                break;

                case 2:
                    printf("Mensaje de paquete demasiado grande");
                break;

                case 3:
                    printf("Time Exceede Message\n");
                    for(int k=0 ; k<8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    switch(binario_decimal(array,8)){
                        case 0:
                            printf("\tEl limite de salto Excedio");
                        break;
                        case 1:
                            printf("\tTiempo de reensamble de fragmento excedido");
                        break;
                    }
                break;

                case 4:
                    printf("Mensaje de problema de parametro\n");
                    for(int k=0 ; k<8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    switch(binario_decimal(array,8)){
                        case 0:
                            printf("\tEl campo del encabezado erroneo encontro");
                        break;
                        case 1:
                            printf("\tEl tipo siguiente desconocido de el encabezado encontro");
                        break;
                        case 2:
                            printf("\tOpcion desconocido del IPV6 encontrada");
                        break;
                    }
                break;

                case 128:
                    printf("Mensaje de pedido de eco");
                break;
                case 129:
                    printf("Mensaje de respuesta de eco");
                break;
                case 133:
                    printf("Mensja de solicitud del router");
                break;
                case 134:
                    printf("Mensaje de anuncio del router");
                break;
                case 135:
                    printf("Mensaje de solicitud vecino");
                break;
                case 136:
                    printf("Mensaje de anuncion de vecino");
                break;
                case 137:
                    printf("Reoriente al mensaje");
                break;
            }
            y=0;
        }
        if(i==335){
            printf("\nChecksum: ");
        }
        if(i>=335 && i<=350){
            array[y]=numeros[cont];
            y++;
        }
        if(i==351){
            printf("%X",binario_decimal(array,16));
        }
        //************************************************************************************************
        if(i==351 && suenio==2){
            printf("\n*******************ENCABEZADO TCP*******************\n");
            printf("\nPuerto origen:");
            y=0;
        }
        if((i>=351 && i<=366) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==367 && suenio==2){
            int x = binario_decimal(array,16);
            printf("%d\n",x);
            funcion_ipv4_tcp(x);
            printf("\nPuerto destino:");
            y=0;
        }
        if((i>=367 && i<=382) && suenio==2){
            array[y]=numeros[cont];//guardamos los siguientes 16 bits en el arreglo
            y++;
        }
        if(i==383 && suenio==2){
            int x = binario_decimal(array,16);
            printf("%d\n",x);//Mostramos el numero decimal
            funcion_ipv4_tcp(x);//Mostramos los datos correspondientes al puerto en la funcion
            printf("\nNumero de secuencia:");
            y=0;
        }
        if((i>=383 && i<=414) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==415 && suenio==2){
            printf("%d",(binario_decimal(array,32)*-1));
            printf("\nAcuse de recibo:");
            y=0;
        }
        if((i>=415 && i<=446) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==447 && suenio==2){
            printf("%02X",binario_decimal(array,32));
            printf("\nLongitud de cabecera: ");
            y=0;
        }
        if((i>=447 && i<=450) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==451 && suenio==2){
            printf("%d",binario_decimal(array,5));
            printf("\nReservado: 000");//algo de trampa xD
            y=0;
        }
        if(i==451 && suenio==2){
            printf("\nBanderas(flags) de comunicacion de TCP\n");
            printf("NS (");
            if(numeros[cont] == 1){
                printf("1):ECN-nonce concealment protection.\n");
            }else{
             printf("0)\n");
            }
        }
        if(i==452 && suenio==2){
            printf("CWR (");
            if(numeros[cont] == 1){
                printf("1):Congestion Window Reduced.\n");
            }else{
                printf("0)\n");
            }
        }
        if(i==453 && suenio==2){
            printf("ECE (");
            if(numeros[cont] == 1){
                printf("1):Para dar indicaciones sobre congestion.\n");
            }else{
                printf("0)\n");
            }
        }

        if(i==454 && suenio==2){
            printf("URG (");
            if(numeros[cont] == 1){
                printf("1):Indica que el campo del puntero urgente es valido.\n");
                band2=1;
            }else{
                printf("0)\n");
                band2=0;
            }
        }
        if(i==459 && suenio==2){
            printf("ACK (");
            if(numeros[cont] == 1){
                printf("1):Indica que el campo de asentimiento es valido. \n");
            }else{
                printf("0)\n");
            }
        }
        if(i==460 && suenio==2){
            printf("PSH (");
            if(numeros[cont] == 1){
                printf("1):Push\n");
            }else{
                printf("0)\n");
            }
        }
        if(i==461 && suenio==2){
            printf("RST (");
            if(numeros[cont] == 1){
                printf("1):Reset\n");
            }else{
                printf("0)\n");
            }
        }

        if(i==462 && suenio==2){
            printf("SYN (");
            if(numeros[cont] == 1){
                printf("1):Synchronice\n");
            }else{
                printf("0)\n");
            }
        }

        if(i==463 && suenio==2){
            printf("FIN (");
            if(numeros[cont] == 1){
                printf("1):Para que el emisor (del paquete) solicite la liberación de la conexión.\n");
            }else{
                printf("0)\n");
                printf("Tamanio de ventana o ventana de recepcion: ");
            }
        }

        if((i>=464 && i<=479) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==480 && suenio==2){
            printf("%d",binario_decimal(array,16));
            printf("\nSuma de verifiacion: ");
            y=0;
        }

        if((i>=480 && i<=495) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==496 && suenio==2){
            printf("%X",binario_decimal(array,16));
            printf("\nPuntero Urgente: ");
            y=0;
        }
        if((i>=496 && i<=511) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==512 && suenio==2){
            if(band2==1){
                printf("%X",binario_decimal(array,16));
            }else{
                printf("0");
            }
            y=0;
        }
        //DNS para TCP ipv6
        if(i==512 && suenio == 2 && DNS==1){
            printf("\n*******************ENCABEZADO DNS*******************\n");
            printf("ID:");
        }
        if((i>=512 && i<=527) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==528 && suenio == 2 && DNS==1){
            printf("%X\n",binario_decimal(array,16));
            printf("QR: %d\n",numeros[cont]);
            y=0;
        }
        if((i>=529 && i<=532) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==533 && suenio == 2 && DNS==1){
            printf("Op code: ");
            switch(binario_decimal(array,4)){
                case 0:printf("Consulta estandar(QUERY)\n");break;
                case 1:printf("Consulta inversa(IQUERY)\n");break;
                case 2:printf("Solicitud del estado del servidor(STATUS)\n");break;
                default:printf("IDK\n");
            }
            printf("AA: %d\n",numeros[cont]);
            y=0;
        }
        if(i==534 && suenio == 2 && DNS==1){
            printf("TC: %d\n",numeros[cont]);

        }
        if(i==535 && suenio == 2 && DNS==1){
            printf("RD: %d\n",numeros[cont]);
        }
        if(i==536 && suenio == 2 && DNS==1){
            printf("RA: %d\n",numeros[cont]);
            printf("Z: ");
        }

        if((i>=537 && i<=539) && suenio == 2 && DNS==1){
            printf("%d",numeros[cont]);
        }
        if((i>=540 && i<=543 ) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==544 && suenio == 2 && DNS==1){
            printf("\nRcode: ");
            switch(binario_decimal(array,4)){
                case 0:printf("Ningun error.\n");break;
                case 1:printf("Error de formato. El servidor fue incapaz de interpretar el mensaje\n");break;
                case 2:printf("Fallo en el servidor. El mensaje no fue procesado debido a un problema con el servidor.\n");break;
                case 3:printf("Error en nombre. El nombre de dominio de la consulta no existe. Solo valido si el bit AA esta activo en la respuesta\n");break;
                case 4:printf("No implementado. El tipo solicitado de consulta no esta implementado en el servidor de nombres\n");break;
                case 5:printf("Rechazado. El servidor rechaza responder por razones politicas. Los demás valores se reservan para su usuario en el futuro.\n");break;
                default:printf("IDK\n");break;
            }
            printf("QDcounts: ");
            y=0;
        }
        //contadores DNS
        if((i>=544 && i<=559) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==560 && suenio == 2 && DNS==1){
            QDcount=binario_decimal(array,16);//guardamos la cantidad de preguntas
            printf("%d\n",QDcount);
            printf("ANcount: ");
            y=0;
        }
        if((i>=560 && i<=575) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==576 && suenio == 2 && DNS==1){
            ANcount = binario_decimal(array,16);
            printf("%d\n",ANcount);
            printf("NScount: ");
            y=0;
        }
        if((i>=576 && i<=591) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==592 && suenio == 2 && DNS==1){
            NScount = binario_decimal(array,16);
            printf("%d\n",NScount);
            printf("ARcount: ");
            y=0;
        }
        if((i>=592 && i<=607) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==608 && suenio == 2 && DNS==1){
            ARcount = binario_decimal(array,16);
            printf("%d\n",ARcount);
            y=0;
        }

        if(i==608 && suenio == 2 && DNS==1){
            //PREGUNTAS
            for(int j=0 ; j < QDcount ; j++){//cantidad de preguntas
                int var=1,fin=1;
                do{
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];//guardamos los ocho bits en el array
                        cont++;
                        i++;
                    }
                    var = binario_decimal(array,8);
                    fin=var;

                    while(var!=0){//mientras var no sea 0 se se hara un bucle
                            for(int m = 0 ; m < 8 ; m++){
                                array[m]=numeros[cont];
                                cont++;
                                i++;
                            }
                            printf("%c", binario_decimal(array,8));
                            var--;
                    }
                    if(fin!=0)
                        printf(".");
                }while(fin != 0);//Se termina de imprimir el link
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTipo: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("A");}break;
                    case 5:{printf("CNAME");}break;
                    case 13:{printf("HINFO");}break;
                    case 15:{printf("MX");}break;
                    case 22:{printf("NS");}break;
                    case 23:{printf("NS");}break;
                }
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nClase: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("IN");}break;
                    case 3:{printf("CH");}break;
                }
            }
            //Se imprimen las respuestas
            for(int j=0 ; j < ANcount ; j++){//cantidad de preguntas
                int var=1,fin=1;
                do{
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    var = binario_decimal(array,8);
                    fin=var;

                    while(var!=0){
                            for(int m = 0 ; m < 8 ; m++){
                                array[m]=numeros[cont];
                                cont++;
                                i++;
                            }
                            printf("%c", binario_decimal(array,8));
                            var--;
                    }
                    if(fin!=0)
                        printf(".");
                }while(fin != 0);//terminamos de imprimir el link

                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTipo: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("A");}break;
                    case 5:{printf("CNAME");}break;
                    case 13:{printf("HINFO");}break;
                    case 15:{printf("MX");}break;
                    case 22:{printf("NS");}break;
                    case 23:{printf("NS");}break;
                }
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nClase: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("IN");}break;
                    case 3:{printf("CH");}break;
                }
                for(int k = 0 ; k < 32 ; k++){
                    array[k]=numeros[cont];
                    i++;
                }
                printf("\nTTL: %d - ",binario_decimal(array,32));
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nLongitud de datos: %d - ",binario_decimal(array,16));

                printf("Respuesta:");
                for(int h=0 ; h<4 ; h++){
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    if(h != 4){
                        printf("%d.",binario_decimal(array,8));
                    }else{printf("%d\n",binario_decimal(array,8));}
                }
            }
        }
        if(i==351 && suenio == 3){
            printf("\n*******************ENCABEZADO UDP*******************\n");//comenzamos el encabezado UDP
            printf("\nPuerto de origen:");
            y=0;
        }
        if((i>= 351 && i<=366) && suenio==3){
            array[y]=numeros[cont];
        }
        if(i==366 && suenio==3){
            int x = binario_decimal(array,16);
            printf("%d\n",x);//Mostramos el numero decimal
            funcion_ipv4_tcp(x);
            printf("\nPuerto de destino:");
            y=0;
        }
        if((i>=366 && i<=381) && suenio==3){
            array[y]=numeros[cont];
            y++;
        }
        if(i==382 && suenio==3){
            int x = binario_decimal(array,16);
            printf("%d\n",x);//Mostramos el numero decimal
            funcion_ipv4_tcp(x);
            printf("\nLongitud Total:");
            y=0;
        }
        if((i>=382 && i<=397) && suenio==3){
            array[y]=numeros[cont];
            y++;
        }
        if(i==398 && suenio==3){
            printf("%d\n",binario_decimal(array,16));
            printf("\nSuma de verifcacion:");
            y=0;
        }
        if((i>=398 && i<=413) && suenio==3){
            array[y]=numeros[cont];//guardamos los siguientes 16 bits en el arreglo
            y++;
        }
        if(i==414 && suenio == 3){
            printf("%d\n",binario_decimal(array,16));
            y=0;
        }
        //DNS para UDP ipv6
        if(i==414 && suenio == 3 && DNS==1){
            printf("\n*******************ENCABEZADO DNS*******************\n");
            printf("ID:");
        }
        if((i>=414 && i<=429) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==430 && suenio == 3 && DNS==1){
            printf("%X\n",binario_decimal(array,16));
            printf("QR: %d\n",numeros[cont]);
            y=0;
        }
        if((i>=431 && i<=434) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==435 && suenio == 3 && DNS==1){
            printf("Op code: ");
            switch(binario_decimal(array,4)){
                case 0:printf("Consulta estandar(QUERY)\n");break;
                case 1:printf("Consulta inversa(IQUERY)\n");break;
                case 2:printf("Solicitud del estado del servidor(STATUS)\n");break;
                default:printf("IDK\n");
            }
            printf("AA: %d\n",numeros[cont]);
            y=0;
        }
        if(i==436 && suenio == 3 && DNS==1){
            printf("TC: %d\n",numeros[cont]);

        }
        if(i==437 && suenio == 3 && DNS==1){
            printf("RD: %d\n",numeros[cont]);
        }
        if(i==438 && suenio == 3 && DNS==1){
            printf("RA: %d\n",numeros[cont]);
            printf("Z: ");
        }

        if((i>=439 && i<=441) && suenio == 3 && DNS==1){
            printf("%d",numeros[cont]);
        }
        if((i>=442 && i<=445 ) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==446 && suenio == 3 && DNS==1){
            printf("\nRcode: ");
            switch(binario_decimal(array,4)){
                case 0:printf("Ningun error.\n");break;
                case 1:printf("Error de formato. El servidor fue incapaz de interpretar el mensaje\n");break;
                case 2:printf("Fallo en el servidor. El mensaje no fue procesado debido a un problema con el servidor.\n");break;
                case 3:printf("Error en nombre. El nombre de dominio de la consulta no existe. Solo valido si el bit AA esta activo en la respuesta\n");break;
                case 4:printf("No implementado. El tipo solicitado de consulta no esta implementado en el servidor de nombres\n");break;
                case 5:printf("Rechazado. El servidor rechaza responder por razones politicas. Los demás valores se reservan para su usuario en el futuro.\n");break;
                default:printf("IDK\n");break;
            }
            printf("QDcounts: ");
            y=0;
        }
        //Contadores
        if((i>=446 && i<=461) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==462 && suenio == 3 && DNS==1){
            QDcount=binario_decimal(array,16);
            printf("%d\n",QDcount);
            printf("ANcount: ");
            y=0;
        }
        if((i>=462 && i<=477) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==478 && suenio == 3 && DNS==1){
            ANcount = binario_decimal(array,16);
            printf("%d\n",ANcount);
            printf("NScount: ");
            y=0;
        }
        if((i>=478 && i<=493) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==494 && suenio == 3 && DNS==1){
            NScount = binario_decimal(array,16);
            printf("%d\n",NScount);
            printf("ARcount: ");
            y=0;
        }
        if((i>=494 && i<=509) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==510 && suenio == 3 && DNS==1){
            ARcount = binario_decimal(array,16);
            printf("%d\n",ARcount);
            y=0;
        }

        if(i==510 && suenio == 3 && DNS==1){
            //IMPRIMIMOS LAS PREGUNTAS
            for(int j=0 ; j < QDcount ; j++){//Numero de preguntas
                int var=1,fin=1;
                do{
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    var = binario_decimal(array,8);
                    fin=var;
                    while(var!=0){
                            for(int m = 0 ; m < 8 ; m++){
                                array[m]=numeros[cont];
                                cont++;
                                i++;
                            }
                            printf("%c", binario_decimal(array,8));
                            var--;
                    }
                    if(fin!=0)
                        printf(".");
                }while(fin != 0);
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTipo: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("A");}break;
                    case 5:{printf("CNAME");}break;
                    case 13:{printf("HINFO");}break;
                    case 15:{printf("MX");}break;
                    case 22:{printf("NS");}break;
                    case 23:{printf("NS");}break;
                }
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nClase: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("IN");}break;
                    case 3:{printf("CH");}break;
                }
            }
            //Imprimimos respuestas
            for(int j=0 ; j < ANcount ; j++){//Numero de preguntas
                int var=1,fin=1;
                do{
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    var = binario_decimal(array,8);
                    fin=var;
                    while(var!=0){
                            for(int m = 0 ; m < 8 ; m++){
                                array[m]=numeros[cont];
                                cont++;
                                i++;
                            }
                            printf("%c", binario_decimal(array,8));
                            var--;
                    }
                    if(fin!=0)
                        printf(".");
                }while(fin != 0);//terminamos de imprimir el link

                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    i++;
                }
                printf("\nTipo: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("A");}break;
                    case 5:{printf("CNAME");}break;
                    case 13:{printf("HINFO");}break;
                    case 15:{printf("MX");}break;
                    case 22:{printf("NS");}break;
                    case 23:{printf("NS");}break;
                }
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nClase: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("IN");}break;
                    case 3:{printf("CH");}break;
                }
                for(int k = 0 ; k < 32 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTTL: %d - ",binario_decimal(array,32));
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    i++;
                }
                printf("\nLongitud de datos: %d - ",binario_decimal(array,16));

                printf("Respuesta:");
                for(int h=0 ; h<4 ; h++){
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    if(h != 4){
                        printf("%d.",binario_decimal(array,8));
                    }else{printf("%d\n",binario_decimal(array,8));}
                }
            }
        }

        if(i==351 && suenio == 4){
            printf("\n*******************ENCABEZADO ICMPv6*******************\n");//comenzamos el encabezado UDP
            printf("\nType:");
            y=0;
        }
        if((i>=351 && i<=358) && suenio==3){
            array[y]=numeros[cont];
            y++;
        }
        if(i==359 && suenio == 4){
            printf("%d\n",binario_decimal(array,8));
            printf("\nCode:");
            y=0;
        }
        if((i>=359 && i<=366) && suenio==3){
            array[y]=numeros[cont];//guardamos los siguientes 16 bits en el arreglo
            y++;
        }
        if(i==367 && suenio == 4){
            printf("%d\n",binario_decimal(array,8));
            printf("\nChecksum:");
            y=0;
        }
        if((i>=367 && i<=382) && suenio==3){
            array[y]=numeros[cont];
            y++;
        }
        if(i==383 && suenio == 4){
            printf("%X\n",binario_decimal(array,8));
            printf("\nPaquete:");
            y=0;
        }
        if((i>=383 && i<=450) && suenio==3){
            printf("%d",numeros[cont]);

        }


    cont++;
    i++;
    }printf("\n");

}

void arp_rarp(int numeros[]){
    int cont=0,y=0, x=0, y2=0, band=1, band2=0;
    int array[32];
    printf("\nTipo de hardware: ");
    int i=0;
    while(i<225){
        if(i<16){
            array[y]=numeros[cont];
            y++;
        }
        if(i==16){
           switch(binario_decimal(array,y)){
                case 1: printf("Ethernet");break;
                case 6: printf("IEEE 802 Networks");break;
                case 7: printf("ARCNET");break;
                case 15: printf("Frame Relay");break;
                case 16: printf("Asynchronous Transfer Modse(ATM)");break;
                case 17: printf("HDLC");break;
                case 18: printf("Fibre Channel");break;
                case 19: printf("Asynchronous Transfer Modse(ATM)");break;
                case 20: printf("Serial Line");break;
           }
            y=0;
            printf("\nTipo de protocolo:");
        }
        if(i>=16 && i<=31){
            array[y]=numeros[cont];
            y++;
        }
        if(i==32){
            printf("%02X: ",binario_decimal(array,y));
            if(binario_decimal(array,y) == 2048){
                printf("(IPV4)\n");
            }
            if(binario_decimal(array,y) == 2054){
                printf("(ARP)\n");
            }
            if(binario_decimal(array,y) == 32821){
                printf("(RARP)\n");
            }
            if(binario_decimal(array,y) == 34525){
                printf("(IPV6)\n");
            }

            y=0;
            printf("Longitud de la direccion de hardware:");
        }
        if(i>=32 && i<=39){
            array[y]=numeros[cont];
            y++;
        }
        if(i==40){
            x=binario_decimal(array,y);
            printf("%d",x);
            y=0;
            printf("\nLongitud de la direccion de protocolo: ");
        }
        if(i>=40 && i<=47){
            array[y]=numeros[cont];
            y++;
        }
        if(i==48){
            y2=binario_decimal(array,y);
            printf("%d",y2);
            y=0;
            printf("\nCodigo de operacion: ");
        }
        if(i>=48 && i<=63){
            array[y]=numeros[cont];
            y++;
        }
        if(i==64){
            switch(binario_decimal(array,y)){
                case 1: printf("Solicitud ARP"); break;
                case 2: printf("Una respuesta ARP");break;
                case 3: printf("Solicitud RARP");break;
                case 4: printf("Respuesta RARP");break;
            }
            y=0;
        }
        if(i==64){
            //band=1
            printf("\nDireccion hardware del emisor (MAC): ");
            while(band <= 6){
                for(int k = 0 ; k < 8 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                if(band != 6){//estatica, que se vea bonito
                    printf("%x-",binario_decimal(array,8));
                }else{printf("%x",binario_decimal(array,8));}
                band++;
            }band=1;
        }
        if(i==112){
            //band=1
            printf("\nDireccion IP del emisor: ");
            while(band <= 4){
                for(int k = 0 ; k < 8 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                if(band != 4){
                    printf("%d.",binario_decimal(array,8));
                }else{printf("%d",binario_decimal(array,8));}
                band++;
            }band=1;
        }

        if(i==144){
            //band=1
            printf("\nDireccion hardware del receptor (MAC): ");
            while(band <= 6){
                for(int k = 0 ; k < 8 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                if(band != 6){
                    printf("%x-",binario_decimal(array,8));
                }else{printf("%x",binario_decimal(array,8));}
                band++;
            }band=1;
        }

        if(i==192){
            //band=1
            printf("\nDireccion IP del receptor: ");
            while(band <= 4){
                for(int k = 0 ; k < 8 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                if(band != 4){
                    printf("%d.",binario_decimal(array,8));
                }else{printf("%d",binario_decimal(array,8));}
                band++;
            }band=1;
        }
        cont++;
        i++;
    }printf("\n");
}

int binario_decimal(int array[], int y){
    int sizearray = y;
    int num = sizearray, res=0;
    int suma = 0;
    for(int i = 0 ; i<sizearray ; i++){
        if(i==sizearray-1 && array[sizearray-1]==1){
            suma = suma+1;
        }
        if(i<sizearray-1 && i != sizearray-1){
            res = pow(2,num-1);
            suma = suma + (array[i]) * res;
            num--;
        }
    }
    return suma;
}

void ipv4(int numeros[]){
    int cont=0,suenio=0,suma2=0,y=0,band=1,band2=0;
    int array[32];
    int i=0;
    while(i<2000){
        if(i==0){printf("Version:");}
        if(i<4){
            array[y]=numeros[cont];
            y++;
        }
        if(i==4){
            printf(" %d",binario_decimal(array,y));
            y=0;
            printf("\nTamanio cabecera:");
        }
        if(i>=4 && i<=7){
            array[y]=numeros[cont];//guardamos los numeros en numerito para convertirlo a decimal
            y++;
        }
        if(i==8){
            printf(" %d",binario_decimal(array,y));
            y=0;
            printf("\nTipo de servicio:");
            printf("\nprimeros 3 bits: \n\t");
        }
        if(i>=8 && i<=10){
            array[y]=numeros[cont];//guardamos los numeros en numerito para convertirlo a decimal
            y++;
        }
        if(i==11){
            switch(binario_decimal(array,y)){
                case 0: printf("(De rutina)");break;
                case 1: printf("(Prioritari)");break;
                case 2: printf("(Inmediato)");break;
                case 3: printf("(Relampago)");break;
                case 4: printf("(Invalidacion relampago)");break;
                case 5: printf("(Procesando llamada critica y de emergencia)");break;
                case 6: printf("(Control de trabajo de internet)");break;
                case 7: printf("(Control de red)");break;
            }
            y=0;
            printf("\nsiguientes 5 bits:\n");
        }
        if(i==11){
            if(numeros[cont]==0){
                printf("\tRetardo: Normal ");
            }else{printf("\tRetardo: Bajo ");
                }
        }
        if(i==12){
            if(numeros[cont]==0){
                printf("\n\tRendimiento: Normal ");
            }else{printf("\n\tRendimiento: Alto ");
                }
        }
        if(i==13){
            if(numeros[cont]==0){
                printf("\n\tFiabilidad: Normal ");
            }else{printf("\n\tFiabilidad: Alto ");
                }
        }
        if(i==14){printf("\n\tBits reservados: ");}
        if(i==16){printf("\nLongitud total:");}
        if(i>=16 && i<=31){
            array[y]=numeros[cont];
            y++;
        }
        if(i==32){
            printf(" %d",binario_decimal(array,y));
            y=0;
            printf("\nIdentificador:");
        }
        if(i>=32 && i<=47){
            array[y]=numeros[cont];
            y++;
        }
        if(i==48){
            printf(" %d",binario_decimal(array,y));
            y=0;
            printf("\nBanderas");
            printf("\n\tBit reservado ");
        }
        if(i==49){
            if(numeros[cont]==0){
                printf("\n\tDivisible ");
            }else{printf("\n\tNo Divisible ");
                }
        }
        if(i==50){
            if(numeros[cont]==0){
                printf("\n\tUltimo Fragmento ");
            }else{printf("\n\tFragmento Intermedio ");
                }
        }
        if(i==51){printf("\nPosicion de fragmento:");}
        if(i>=51 && i<=63){
            array[y]=numeros[cont];
            y++;
        }
        if(i==64){
            printf(" %d",binario_decimal(array,y));
            y=0;
            printf("\nTiempo de vida:");
        }
        if(i>=64 && i<=71){
            array[y]=numeros[cont];
            y++;
        }
        if(i==72){
            printf(" %d",binario_decimal(array,y));
            y=0;
            printf("\nProtocolo:");
        }
        if(i>=72 && i<=79){
            array[y]=numeros[cont];
            y++;
        }
        if(i==80){
            switch(binario_decimal(array,y)){
                case 1: printf("(ICMP v4)\n"); suenio=1;break;
                case 6: printf("(TCP)\n");suenio=2;break;
                case 17: printf("(UDP)\n");suenio=3;break;
                case 58: printf("(ICMPv6)\n");suenio=4;break;
                case 118: printf("(STP)\n");suenio=5;break;
                case 121: printf("(SMP)\n");suenio=6;break;
            }
            y=0;
            printf("Suma de control de cabecera:");
        }
        if(i>=80 && i<=95){
            array[y]=numeros[cont];
            y++;
        }
        if(i==96){
            printf("%x\n",binario_decimal(array,y));
            y=0;
        }
        if(i==96 ){
            //band=1
            printf("Direccion ip de origen:");
            while(band <= 4){
                for(int k = 0 ; k < 8 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                if(band != 4){
                    printf("%d.",binario_decimal(array,8));
                }else{printf("%d\n",binario_decimal(array,8));}
                band++;
            }band=1;
        }

        if(i==128 ){
            printf("\nDireccion ip de destino:");
            //band=1
            while(band <= 4){
                for(int k = 0 ; k < 8 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                if(band != 4){
                    printf("%d.",binario_decimal(array,8));
                }else{printf("%d",binario_decimal(array,8));}
                band++;
            }band=1;
        }

        if(i==160){printf("\n");}
        if(i>=160 && suenio==1){//Encabezado ICMP
            if(i>=160 && i<=167){
                array[y]=numeros[cont];
                y++;
            }
            if(i==168){
                suma2=binario_decimal(array,y);
                y=0;
            }
        }

        if(i==168 && suenio==1){
            printf("\n\t*******************ICMP*******************\n");
            printf("Type:");
            switch(suma2){
                case 0: printf("Echo Reply(respuesta de eco");break;
                case 3: printf("Destination Unreachable(destino inaccesible)");break;
                case 4: printf("Source Quench (disminución del tráfico desde el origen)");break;
                case 5: printf("Redirect (redireccionar - cambio de ruta) ");break;
                case 8: printf("Echo (solicitud de eco) ");break;
                case 11: printf("Time Exceeded (tiempo excedido para un datagrama) ");break;
                case 12: printf("Parameter Problem (problema de parámetros )");break;
                case 13: printf("Timestamp (solicitud de marca de tiempo)");break;
                case 14: printf("Timestamp Reply (respuesta de marca de tiempo)");break;
                case 15: printf("Information Request (solicitud de información) - obsoleto-");break;
                case 16: printf("Information Reply (respuesta de información) - obsoleto- ");break;
                case 17: printf("Addressmask (solicitud de máscara de dirección)");break;
                case 18: printf("Anddressmask Reply (respuesta de mascara de direccion)");break;
            }
        }
        if(i>=168 && suenio==1){
            if(i>=168 && i<=175){
                array[y]=numeros[cont];
                y++;
            }
            if(i==176){
                printf("%d", binario_decimal(array,y));
                y=0;
                suma2=binario_decimal(array,y);
            }
        }
        if(i==176 && suenio==1){
            printf("\nCode:");
            switch(suma2){
                case 0: printf("no se puede llegar a la red");break;
                case 1: printf("no se puede llegar al host o aplicación de destino");break;
                case 2: printf("el destino no dispone del protocolo solicitado");break;
                case 3: printf("no se puede llegar al puerto destino o la aplicación destino no está libre");break;
                case 4: printf("se necesita aplicar fragmentación, pero el flag correspondiente indica lo contrario");break;
                case 5: printf("la ruta de origen no es correcta");break;
                case 6: printf("no se conoce la red destino");break;
                case 7: printf("no se conoce el host destino");break;
                case 8: printf("el host origen está aislado");break;
                case 9: printf("la comunicación con la red destino está prohibida por razones administrativas");break;
                case 10: printf("la comuicacion con el host destino esta prohibida por razones administrativas");break;
                case 11: printf("no se puede llegar a la red destinodebido al Tipo de servicio");break;
                case 12: printf("no se puede llegar al host destino debido al Tipo de servicio");break;
            }
            printf("\n");
        }
        if(i>=176 && suenio==1){
            if(i>=176 && i<=191){
                array[y]=numeros[cont];
                y++;
            }
            if(i==177){
                printf("Checksum: %X\n",binario_decimal(array,y));
                y=0;
            }
        }
        if(i==160 && suenio==2){
            printf("\n*******************ENCABEZADO TCP*******************\n");//comenzamos el encabezado tcp
            printf("\nPuerto de origen:");
            y=0;
        }
        if((i>=160 && i<=175) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==176 && suenio==2){
            int x = binario_decimal(array,16);
            printf("%d\n",x);
            funcion_ipv4_tcp(x);
            printf("\nPuerto de destino:");
            y=0;
        }
        if((i>=176 && i<=191) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==192 && suenio==2){
            int x = binario_decimal(array,16);
            printf("%d\n",x);
            funcion_ipv4_tcp(x);

            printf("\nNumero de secuencia:");
            y=0;
        }
        if((i>= 192 && i<= 223) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==224 && suenio==2){
            printf("%d",(binario_decimal(array,32)*-1));
            printf("\nNumero de acuse de recibo:");
            y=0;
        }
        if((i>=224 && i<=255) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==256 && suenio==2){
            printf("%02X",binario_decimal(array,32));
            printf("\nLongitud de cabecera: ");
            y=0;
        }

        if((i>=256 && i<=259) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==263 && suenio==2){
            printf("%d",binario_decimal(array,5));
            printf("\nReservado: 000");
            y=0;
        }
        if(i==263 && suenio==2){
            printf("\nBanderas(flags) de comunicacion de TCP\n");
            printf("NS (");
            if(numeros[cont] == 1){
                printf("1):ECN-nonce concealment protection.\n");
            }else{
             printf("0)\n");
            }
        }
        if(i==264 && suenio==2){
            printf("CWR (");
            if(numeros[cont] == 1){
                printf("1):Congestion Window Reduced.\n");
            }else{
                printf("0)\n");
            }
        }
        if(i==265 && suenio==2){
            printf("ECE (");
            if(numeros[cont] == 1){
                printf("1):Para dar indicaciones sobre congestion.\n");
            }else{
                printf("0)\n");
            }
        }

        if(i==266 && suenio==2){
            printf("URG (");
            if(numeros[cont] == 1){
                printf("1):Indica que el campo del puntero urgente es valido.\n");
                band2=1;
            }else{
                printf("0)\n");
                band2=0;
            }
        }
        if(i==267 && suenio==2){
            printf("ACK (");
            if(numeros[cont] == 1){
                printf("1):Indica que el campo de asentimiento es valido. \n");
            }else{
                printf("0)\n");
            }
        }
        if(i==268 && suenio==2){
            printf("PSH (");
            if(numeros[cont] == 1){
                printf("1):Push\n");
            }else{
                printf("0)\n");
            }
        }
        if(i==269 && suenio==2){
            printf("RST (");
            if(numeros[cont] == 1){
                printf("1):Reset\n");
            }else{
                printf("0)\n");
            }
        }

        if(i==270 && suenio==2){
            printf("SYN (");
            if(numeros[cont] == 1){
                printf("1):Synchronice\n");
            }else{
                printf("0)\n");
            }
        }

        if(i==271 && suenio==2){
            printf("FIN (");
            if(numeros[cont] == 1){
                printf("1):Para que el emisor (del paquete) solicite la liberación de la conexión.\n");
            }else{
                printf("0)\n");
                printf("Tamanio de ventana o ventana de recepcion: ");
            }
        }

        if((i>=272 && i<=287) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==288 && suenio==2){
            printf("%d",binario_decimal(array,16));
            printf("\nSuma de verifiacion: ");
            y=0;
        }

        if((i>=288 && i<=303) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==304 && suenio==2){
            printf("%X",binario_decimal(array,16));
            printf("\nPuntero Urgente: ");
            y=0;
        }
        if((i>=304 && i<= 319) && suenio==2){
            array[y]=numeros[cont];
            y++;
        }
        if(i==320 && suenio==2){
            if(band2=1){
                printf("%X",binario_decimal(array,16));
            }else{
                printf("0");
            }
            y=0;
        }
        //DNS para TCP
        if(i==320 && suenio == 2 && DNS==1){
            printf("\n*******************ENCABEZADO DNS*******************\n");
            printf("ID:");
        }
        if((i>=320 && i<=335) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==336 && suenio == 2 && DNS==1){
            printf("%X\n",binario_decimal(array,16));
            printf("QR: %d\n",numeros[cont]);
            y=0;
        }
        if((i>=337 && i<=340) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==341 && suenio == 2 && DNS==1){
            printf("Op code: ");
            switch(binario_decimal(array,4)){
                case 0:printf("Consulta estandar(QUERY)\n");break;
                case 1:printf("Consulta inversa(IQUERY)\n");break;
                case 2:printf("Solicitud del estado del servidor(STATUS)\n");break;
                default:printf("IDK\n");
            }
            printf("AA: %d\n",numeros[cont]);
            y=0;
        }
        if(i==342 && suenio == 2 && DNS==1){
            printf("TC: %d\n",numeros[cont]);

        }
        if(i==343 && suenio == 2 && DNS==1){
            printf("RD: %d\n",numeros[cont]);
        }
        if(i==344 && suenio == 2 && DNS==1){
            printf("RA: %d\n",numeros[cont]);
            printf("Z: ");
        }

        if((i>=345 && i<=347) && suenio == 2 && DNS==1){
            printf("%d",numeros[cont]);
        }
        if((i>=348 && i<=351 ) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==352 && suenio == 2 && DNS==1){
            printf("\nRcode: ");
            switch(binario_decimal(array,4)){
                case 0:printf("Ningun error.\n");break;
                case 1:printf("Error de formato. El servidor fue incapaz de interpretar el mensaje\n");break;
                case 2:printf("Fallo en el servidor. El mensaje no fue procesado debido a un problema con el servidor.\n");break;
                case 3:printf("Error en nombre. El nombre de dominio de la consulta no existe. Solo valido si el bit AA esta activo en la respuesta\n");break;
                case 4:printf("No implementado. El tipo solicitado de consulta no esta implementado en el servidor de nombres\n");break;
                case 5:printf("Rechazado. El servidor rechaza responder por razones politicas. Los demás valores se reservan para su usuario en el futuro.\n");break;
                default:printf("IDK\n");break;
            }
            printf("QDcounts: ");
            y=0;
        }
        //contadores DNS
        if((i>=352 && i<=367) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==368 && suenio == 2 && DNS==1){
            QDcount=binario_decimal(array,16);
            printf("%d\n",QDcount);
            printf("ANcount: ");
            y=0;
        }
        if((i>=368 && i<=383) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==384 && suenio == 2 && DNS==1){
            ANcount = binario_decimal(array,16);
            printf("%d\n",ANcount);
            printf("NScount: ");
            y=0;
        }
        if((i>=384 && i<=399) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==400 && suenio == 2 && DNS==1){
            NScount = binario_decimal(array,16);
            printf("%d\n",NScount);
            printf("ARcount: ");
            y=0;
        }
        if((i>=400 && i<=415) && suenio == 2 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==416 && suenio == 2 && DNS==1){
            ARcount = binario_decimal(array,16);
            printf("%d\n",ARcount);
            y=0;
        }

        if(i==416 && suenio == 2 && DNS==1){
            //Se imprimen las preguintas
            for(int j=0 ; j < QDcount ; j++){//cantidad de preguntas
                int var=1,fin=1;
                do{
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    var = binario_decimal(array,8);
                    fin=var;
                    while(var!=0){
                            for(int m = 0 ; m < 8 ; m++){
                                array[m]=numeros[cont];
                                cont++;
                                i++;
                            }
                            printf("%c", binario_decimal(array,8));
                            var--;
                    }
                    if(fin!=0)
                        printf(".");
                }while(fin != 0);
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTipo: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("A");}break;
                    case 5:{printf("CNAME");}break;
                    case 13:{printf("HINFO");}break;
                    case 15:{printf("MX");}break;
                    case 22:{printf("NS");}break;
                    case 23:{printf("NS");}break;
                }
                for(int k = 0 ; k < 16 ; k++){//Ahora recorremos los siguentes dos campos de la pregunta
                    array[k]=numeros[cont];//guardamos los ocho bits en el array
                    cont++;
                    i++;
                }
                printf("\nClase: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("IN");}break;
                    case 3:{printf("CH");}break;
                }
            }
            //Imprimimos respuestas
            for(int j=0 ; j < ANcount ; j++){//cantidad de preguntas
                int var=1,fin=1;
                do{
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    var = binario_decimal(array,8);
                    fin=var;
                    while(var!=0){
                            for(int m = 0 ; m < 8 ; m++){
                                array[m]=numeros[cont];
                                cont++;
                                i++;
                            }
                            printf("%c", binario_decimal(array,8));
                            var--;
                    }
                    if(fin!=0)
                        printf(".");
                }while(fin != 0);//terminamos de imprimir el link

                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTipo: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("A");}break;
                    case 5:{printf("CNAME");}break;
                    case 13:{printf("HINFO");}break;
                    case 15:{printf("MX");}break;
                    case 22:{printf("NS");}break;
                    case 23:{printf("NS");}break;
                }
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nClase: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("IN");}break;
                    case 3:{printf("CH");}break;
                }
                for(int k = 0 ; k < 32 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTTL: %d - ",binario_decimal(array,32));
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nLongitud de datos: %d - ",binario_decimal(array,16));

                printf("Respuesta:");
                for(int h=0 ; h<4 ; h++){
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    if(h != 4){
                        printf("%d.",binario_decimal(array,8));
                    }else{printf("%d\n",binario_decimal(array,8));}
                }
            }
        }
        if(i==160 && suenio == 3 ){
            printf("\n*******************ENCABEZADO UDP*******************\n");
            printf("\nPuerto de origen:");
            y=0;
        }
        if((i>=160 && i<=175) && suenio==3){
            array[y]=numeros[cont];
            y++;
        }
        if(i==176 && suenio==3){
            int x = binario_decimal(array,16);
            printf("%d\n",x);
            funcion_ipv4_tcp(x);

            printf("\nPuerto de destino:");
            y=0;
        }
        if((i>=176 && i<=191) && suenio==3){
            array[y]=numeros[cont];
            y++;
        }
        if(i==192 && suenio==3){
            int x = binario_decimal(array,16);
            printf("%d\n",x);
            funcion_ipv4_tcp(x);
            printf("\nLongitud Total:");
            y=0;
        }
        if((i>=192 && i<=207) && suenio==3){
            array[y]=numeros[cont];
            y++;
        }
        if(i==208 && suenio==3){
            printf("%d\n",binario_decimal(array,16));
            printf("\nSuma de verifcacion:");
            y=0;
        }
        if((i>=208 && i<=223) && suenio==3){
            array[y]=numeros[cont];
            y++;
        }

        if(i==224 && suenio == 3){
            printf("%d\n",binario_decimal(array,16));
            y=0;
        }
        //DNS para UDP
        if(i==224 && suenio == 3 && DNS==1){
            printf("\n*******************ENCABEZADO DNS*******************\n");
            printf("ID:");
        }
        if((i>=224 && i<=239) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==240 && suenio == 3 && DNS==1){
            printf("%X\n",binario_decimal(array,16));
            printf("QR: %d\n",numeros[cont]);
            y=0;
        }
        if((i>=241 && i<=244) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==245 && suenio == 3 && DNS==1){
            printf("Op code: ");
            switch(binario_decimal(array,4)){
                case 0:printf("Consulta estandar(QUERY)\n");break;
                case 1:printf("Consulta inversa(IQUERY)\n");break;
                case 2:printf("Solicitud del estado del servidor(STATUS)\n");break;
                default:printf("IDK\n");
            }
            printf("AA: %d\n",numeros[cont]);
            y=0;
        }
        if(i==246 && suenio == 3 && DNS==1){
            printf("TC: %d\n",numeros[cont]);

        }
        if(i==247 && suenio == 3 && DNS==1){
            printf("RD: %d\n",numeros[cont]);
        }
        if(i==248 && suenio == 3 && DNS==1){
            printf("RA: %d\n",numeros[cont]);
            printf("Z: ");
        }

        if((i>=249 && i<=251) && suenio == 3 && DNS==1){
            printf("%d",numeros[cont]);
        }
        if((i>=252 && i<=255 ) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==256 && suenio == 3 && DNS==1){
            printf("\nRcode: ");
            switch(binario_decimal(array,4)){
                case 0:printf("Ningun error.\n");break;
                case 1:printf("Error de formato. El servidor fue incapaz de interpretar el mensaje\n");break;
                case 2:printf("Fallo en el servidor. El mensaje no fue procesado debido a un problema con el servidor.\n");break;
                case 3:printf("Error en nombre. El nombre de dominio de la consulta no existe. Solo valido si el bit AA esta activo en la respuesta\n");break;
                case 4:printf("No implementado. El tipo solicitado de consulta no esta implementado en el servidor de nombres\n");break;
                case 5:printf("Rechazado. El servidor rechaza responder por razones politicas. Los demás valores se reservan para su usuario en el futuro.\n");break;
                default:printf("IDK\n");break;
            }
            printf("QDcounts: ");
            y=0;
        }
        //contadores DNS
        if((i>=256 && i<=271) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==272 && suenio == 3 && DNS==1){
            QDcount=binario_decimal(array,16);//guardamos la cantidad de preguntas
            printf("%d\n",QDcount);
            printf("ANcount: ");
            y=0;
        }
        if((i>=272 && i<=287) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==288 && suenio == 3 && DNS==1){
            ANcount = binario_decimal(array,16);
            printf("%d\n",ANcount);
            printf("NScount: ");
            y=0;
        }
        if((i>=288 && i<=303) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==304 && suenio == 3 && DNS==1){
            NScount = binario_decimal(array,16);
            printf("%d\n",NScount);
            printf("ARcount: ");
            y=0;
        }
        if((i>=304 && i<=319) && suenio == 3 && DNS==1){
            array[y]=numeros[cont];
            y++;
        }
        if(i==320 && suenio == 3 && DNS==1){
            ARcount = binario_decimal(array,16);
            printf("%d\n",ARcount);
            y=0;
        }

        if(i==320 && suenio == 3 && DNS==1){
            for(int j=0 ; j < QDcount ; j++){//cantidad de preguntas
                int var=1,fin=1;
                do{
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    var = binario_decimal(array,8);
                    fin=var;
                    while(var!=0){
                            for(int m = 0 ; m < 8 ; m++){
                                array[m]=numeros[cont];
                                cont++;
                                i++;
                            }
                            printf("%c", binario_decimal(array,8));
                            var--;
                    }
                    if(fin!=0)
                        printf(".");
                }while(fin != 0);
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTipo: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("A");}break;
                    case 5:{printf("CNAME");}break;
                    case 13:{printf("HINFO");}break;
                    case 15:{printf("MX");}break;
                    case 22:{printf("NS");}break;
                    case 23:{printf("NS");}break;
                }
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nClase: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("IN");}break;
                    case 3:{printf("CH");}break;
                }
            }
            for(int j=0 ; j < ANcount ; j++){//cantidad de preguntas
                int var=1,fin=1;
                do{
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    var = binario_decimal(array,8);
                    fin=var;
                    while(var!=0){
                            for(int m = 0 ; m < 8 ; m++){
                                array[m]=numeros[cont];
                                cont++;
                                i++;
                            }
                            printf("%c", binario_decimal(array,8));
                            var--;
                    }
                    if(fin!=0)
                        printf(".");
                }while(fin != 0);//terminamos de imprimir el link

                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTipo: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("A");}break;
                    case 5:{printf("CNAME");}break;
                    case 13:{printf("HINFO");}break;
                    case 15:{printf("MX");}break;
                    case 22:{printf("NS");}break;
                    case 23:{printf("NS");}break;
                }
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nClase: %d - ",binario_decimal(array,16));
                switch(binario_decimal(array,16)){
                    case 1:{printf("IN");}break;
                    case 3:{printf("CH");}break;
                }
                for(int k = 0 ; k < 32 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nTTL: %d - ",binario_decimal(array,32));
                for(int k = 0 ; k < 16 ; k++){
                    array[k]=numeros[cont];
                    cont++;
                    i++;
                }
                printf("\nLongitud de datos: %d - ",binario_decimal(array,16));

                printf("Respuesta:");
                for(int h=0 ; h<4 ; h++){
                    for(int k = 0 ; k < 8 ; k++){
                        array[k]=numeros[cont];
                        cont++;
                        i++;
                    }
                    if(h != 4){
                        printf("%d.",binario_decimal(array,8));
                    }else{printf("%d\n",binario_decimal(array,8));}
                }
            }
        }

//***********************************************************************
        if((i>=8 && i<=15) || (i>=48 && i<=50)){printf("%d",numeros[cont]);}
        cont++;
        i++;
    }printf("\n");
}

void funcion_ipv4_tcp(int x){
    if(x>=0 && x<=1023){
                printf("\tPuertos bien conocidos");
                switch(x){
                    case 20: printf("\tServicio: FTP"); break;
                    case 21: printf("\tServicio: FTP"); break;
                    case 22: printf("\tServicio: SSH"); break;
                    case 23: printf("\tServicio: TELNET"); break;
                    case 25: printf("\tServicio: SMTP"); break;
                    case 53:
                        printf("\tServicio: DNS");
                        DNS=1;
                    break;
                    case 67: printf("\tServicio: DHCP"); break;
                    case 68: printf("\tServicio: DHCP"); break;
                    case 69: printf("\tServicio: TFTP"); break;
                    case 80: printf("\tServicio: HTTP"); break;
                    case 110: printf("\tServicio: POP3"); break;
                    case 143: printf("\tServicio: IMAP"); break;
                    case 443: printf("\tServicio: HTTPS"); break;
                    case 993: printf("\tServicio: IMAP SSL"); break;
                    case 995: printf("\tServicio: POP SSL"); break;
                }
            }
            if(x>=1024 && x<=49151)
                printf("\tPuertos Registrados\n");
            if(x>=49152 && x<=65535)
                printf("\tPuertos Dinamicos o Privado\n");
}

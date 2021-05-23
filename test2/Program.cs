using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.Threading;


namespace test2
{
    class Program
    {
        static PacketDevice selectedDevic = null;
       
        static string path = "file.pcap";
        static string choos = null;

        static void Main(string[] args)
        {
            Console.WriteLine("1. Приём пакетов и запись в файл \n" + "2. Открытие файла");

            re:
            Console.Write("> ");

            choos = Console.ReadLine();

            switch (choos)
            {
                case "1":
                    // записывается название{--}
                    IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

                    if (allDevices.Count == 0)
                    {
                        Console.WriteLine("Устройства не неайдены");
                        return;
                    }

                    // Распечатать список
                    for (int i = 0; i != allDevices.Count; ++i)
                    {
                        //Имя- всё до }
                        LivePacketDevice device = allDevices[i];
                        Console.Write((i + 1) + ". " + device.Name);
                        if (device.Description != null)
                            //Описание- после {}:(Network...)
                            Console.WriteLine(" (" + device.Description + ")");
                        else
                            Console.WriteLine(" (Нет устройств)");
                    }

                    int deviceIndex = 0;
                    do
                    {
                        Console.WriteLine();
                        Console.WriteLine("Выберите устройство (1-" + allDevices.Count + "):");
                        Console.Write("> ");
                        string deviceIndexString = Console.ReadLine();
                        if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                            deviceIndex < 1 || deviceIndex > allDevices.Count)
                        {
                            deviceIndex = 0;
                        }
                    } while (deviceIndex == 0);

                    //Взять выбранный адаптер
                    selectedDevic = allDevices[deviceIndex - 1];

                    // Открыть дивайсы\устройства
                    //1.часть пакета для захвата;65536 гарантирует, что весь пакет будет захвачен на всех уровнях связи
                    //2-неразборчивый режим и 3-тайм-аут чтения
                    using (PacketCommunicator communicator = selectedDevic.Open(65536, PacketDeviceOpenAttributes.Promiscuous,1000)) 
                    {
                        Thread th1;
                        th1 = new Thread(() => { communicator.ReceivePackets(0, PacketHandler); });

                        Thread th2;
                        th2 = new Thread(() => { communicator.ReceivePackets(0, PacketHandl); });

                        Console.WriteLine();
                        Console.WriteLine("Для завершения и сохранения нажмите Ctrl+C");
                        Console.WriteLine();

                        Thread.Sleep(200);

                        th1.Start();
                        th2.Start();
                        th1.Join();
                        th2.Join();
                    }

                break;

                case "2":

                    OfflinePacketDevice selectedDevice = new OfflinePacketDevice(path);

                    using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))                                  
                    {
                        // Считать и отправить пакеты до тех пор, пока не будет достигнут EOF
                        communicator.ReceivePackets(0, DispatcherHandler);
                    }

                break;

                default:
                    Console.WriteLine("Выберете 1 или 2");
                    goto re;
                    
            };
        }

        private static void PacketHandler(Packet packet)
        {
            using (PacketCommunicator communicator = selectedDevic.Open(65536, PacketDeviceOpenAttributes.Promiscuous,1000)) 
            {
                using (PacketDumpFile file = communicator.OpenDump("file.pcap"))
                {
                    communicator.ReceivePackets(0, file.Dump);
                }
            }
        }

        private static void PacketHandl(Packet packet)
        {
            // печать метки времени и длины пакета
            Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);

            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;

            // печать ip-адресов и портов udp
            Console.WriteLine(ip.Source + ":" + udp.SourcePort + " -> " + ip.Destination + ":" + udp.DestinationPort);
            Console.WriteLine(packet.Ethernet.IpV4.Protocol);

            Console.WriteLine("");
        }

        private static void DispatcherHandler(Packet packet)
        {
            Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Count);
            Console.WriteLine(packet.Ethernet.IpV4.Source + ":" + packet.Ethernet.IpV4.Tcp.SourcePort + " -> " + packet.Ethernet.IpV4.IpV4.Destination + ":" + packet.Ethernet.IpV4.Udp.DestinationPort);

            // Console.WriteLine(packet.IpV4.Tcp.UrgentPointer);

            Console.WriteLine(packet.IpV4.Udp);
            //Адрес назвачения 
            Console.WriteLine(packet.Ethernet.Destination);

            // Распечатать пакет
            const int LineLength = 64;
            for (int i = 0; i != packet.Length; ++i)
            {
                Console.Write(packet[i].ToString("X2"));
                if ((i + 1) % LineLength == 0) 
                    Console.WriteLine();
            }

            Console.WriteLine();
            Console.WriteLine();
        }
    }
}

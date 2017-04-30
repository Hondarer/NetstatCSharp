// Based on 'C# Sample to list all the active TCP and UDP connections using Windows Form appl' by OneCode.
// https://code.msdn.microsoft.com/windowsdesktop/C-Sample-to-list-all-the-4817b58f

// http://stackoverflow.com/questions/13246099/using-c-sharp-to-reference-a-port-number-to-service-name

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

namespace NetstatCSharp
{
    /// <summary>
    /// 
    /// </summary>
    class Program
    {
        /// <summary>
        /// Enum for protocol types.
        /// </summary>
        public enum Protocol
        {
            tcp,
            udp
        }

        // Enum to define the set of values used to indicate the type of table returned by 
        // calls made to the function 'GetExtendedTcpTable'.
        public enum TcpTableClass
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        // Enum to define the set of values used to indicate the type of table returned by calls
        // made to the function GetExtendedUdpTable.
        public enum UdpTableClass
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        // Enum for different possible states of TCP connection
        public enum MibTcpState
        {
            CLOSED = 1,
            LISTENING = 2,
            SYN_SENT = 3,
            SYN_RCVD = 4,
            ESTABLISHED = 5,
            FIN_WAIT1 = 6,
            FIN_WAIT2 = 7,
            CLOSE_WAIT = 8,
            CLOSING = 9,
            LAST_ACK = 10,
            TIME_WAIT = 11,
            DELETE_TCB = 12,
            NONE = 0
        }

        /// <summary>
        /// The structure contains information that describes an IPv4 TCP connection with 
        /// IPv4 addresses, ports used by the TCP connection, and the specific process ID
        /// (PID) associated with connection.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public MibTcpState state;
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;
            public uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] remotePort;
            public int owningPid;
        }

        /// <summary>
        /// The structure contains a table of process IDs (PIDs) and the IPv4 TCP links that 
        /// are context bound to these PIDs.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
                SizeConst = 1)]
            public MIB_TCPROW_OWNER_PID[] table;
        }

        /// <summary>
        /// This class provides access an IPv4 TCP connection addresses and ports and its
        /// associated Process IDs and names.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public class TcpProcessRecord
        {
            public IPAddress LocalAddress { get; set; }
            public ushort LocalPort { get; set; }
            public IPAddress RemoteAddress { get; set; }
            public ushort RemotePort { get; set; }
            public MibTcpState State { get; set; }
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }

            public TcpProcessRecord(IPAddress localIp, IPAddress remoteIp, ushort localPort,
                ushort remotePort, int pId, MibTcpState state)
            {
                LocalAddress = localIp;
                RemoteAddress = remoteIp;
                LocalPort = localPort;
                RemotePort = remotePort;
                State = state;
                ProcessId = pId;
                // Getting the process name associated with a process id.
                if (Process.GetProcesses().Any(process => process.Id == pId))
                {
                    ProcessName = Process.GetProcessById(ProcessId).ProcessName;
                }
            }
        }

        /// <summary>
        /// The structure contains an entry from the User Datagram Protocol (UDP) listener
        /// table for IPv4 on the local computer. The entry also includes the process ID
        /// (PID) that issued the call to the bind function for the UDP endpoint.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;
            public int owningPid;
        }

        /// <summary>
        /// The structure contains the User Datagram Protocol (UDP) listener table for IPv4
        /// on the local computer. The table also includes the process ID (PID) that issued
        /// the call to the bind function for each UDP endpoint.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct,
                SizeConst = 1)]
            public UdpProcessRecord[] table;
        }

        /// <summary>
        /// This class provides access an IPv4 UDP connection addresses and ports and its
        /// associated Process IDs and names.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public class UdpProcessRecord
        {
            public IPAddress LocalAddress { get; set; }
            public uint LocalPort { get; set; }
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }

            public UdpProcessRecord(IPAddress localAddress, uint localPort, int pId)
            {
                LocalAddress = localAddress;
                LocalPort = localPort;
                ProcessId = pId;
                if (Process.GetProcesses().Any(process => process.Id == pId))
                    ProcessName = Process.GetProcessById(ProcessId).ProcessName;
            }
        }

        // The version of IP used by the TCP/UDP endpoint. AF_INET is used for IPv4.
        private const int AF_INET = 2;

        // The GetExtendedTcpTable function retrieves a table that contains a list of
        // TCP endpoints available to the application. Decorating the function with
        // DllImport attribute indicates that the attributed method is exposed by an
        // unmanaged dynamic-link library 'iphlpapi.dll' as a static entry point.
        [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

        // The GetExtendedUdpTable function retrieves a table that contains a list of
        // UDP endpoints available to the application. Decorating the function with
        // DllImport attribute indicates that the attributed method is exposed by an
        // unmanaged dynamic-link library 'iphlpapi.dll' as a static entry point.
        [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize,
            bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved = 0);

        /// <summary>
        /// This function reads and parses the active TCP socket connections available
        /// and stores them in a list.
        /// </summary>
        /// <returns>
        /// It returns the current set of TCP socket connections which are active.
        /// </returns>
        /// <exception cref="OutOfMemoryException">
        /// This exception may be thrown by the function Marshal.AllocHGlobal when there
        /// is insufficient memory to satisfy the request.
        /// </exception>
        private static List<TcpProcessRecord> GetAllTcpConnections()
        {
            int bufferSize = 0;
            List<TcpProcessRecord> tcpTableRecords = new List<TcpProcessRecord>();

            // Getting the size of TCP table, that is returned in 'bufferSize' variable.
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET,
                TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

            // Allocating memory from the unmanaged memory of the process by using the
            // specified number of bytes in 'bufferSize' variable.
            IntPtr tcpTableRecordsPtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                // The size of the table returned in 'bufferSize' variable in previous
                // call must be used in this subsequent call to 'GetExtendedTcpTable'
                // function in order to successfully retrieve the table.
                result = GetExtendedTcpTable(tcpTableRecordsPtr, ref bufferSize, true,
                    AF_INET, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

                // Non-zero value represent the function 'GetExtendedTcpTable' failed,
                // hence empty list is returned to the caller function.
                if (result != 0)
                    return new List<TcpProcessRecord>();

                // Marshals data from an unmanaged block of memory to a newly allocated
                // managed object 'tcpRecordsTable' of type 'MIB_TCPTABLE_OWNER_PID'
                // to get number of entries of the specified TCP table structure.
                MIB_TCPTABLE_OWNER_PID tcpRecordsTable = (MIB_TCPTABLE_OWNER_PID)
                                        Marshal.PtrToStructure(tcpTableRecordsPtr,
                                        typeof(MIB_TCPTABLE_OWNER_PID));
                IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr +
                                        Marshal.SizeOf(tcpRecordsTable.dwNumEntries));

                // Reading and parsing the TCP records one by one from the table and
                // storing them in a list of 'TcpProcessRecord' structure type objects.
                for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.
                        PtrToStructure(tableRowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    tcpTableRecords.Add(new TcpProcessRecord(
                                          new IPAddress(tcpRow.localAddr),
                                          new IPAddress(tcpRow.remoteAddr),
                                          BitConverter.ToUInt16(new byte[2] {
                                              tcpRow.localPort[1],
                                              tcpRow.localPort[0] }, 0),
                                          BitConverter.ToUInt16(new byte[2] {
                                              tcpRow.remotePort[1],
                                              tcpRow.remotePort[0] }, 0),
                                          tcpRow.owningPid, tcpRow.state));
                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                }
            }
            catch (OutOfMemoryException outOfMemoryException)
            {
                //MessageBox.Show(outOfMemoryException.Message, "Out Of Memory",
                //    MessageBoxButtons.OK, MessageBoxIcon.Stop);
            }
            catch (Exception exception)
            {
                //MessageBox.Show(exception.Message, "Exception",
                //    MessageBoxButtons.OK, MessageBoxIcon.Stop);
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTableRecordsPtr);
            }
            return tcpTableRecords != null ? tcpTableRecords.Distinct()
                .ToList<TcpProcessRecord>() : new List<TcpProcessRecord>();
        }

        /// <summary>
        /// This function reads and parses the active UDP socket connections available
        /// and stores them in a list.
        /// </summary>
        /// <returns>
        /// It returns the current set of UDP socket connections which are active.
        /// </returns>
        /// <exception cref="OutOfMemoryException">
        /// This exception may be thrown by the function Marshal.AllocHGlobal when there
        /// is insufficient memory to satisfy the request.
        /// </exception>
        private static List<UdpProcessRecord> GetAllUdpConnections()
        {
            int bufferSize = 0;
            List<UdpProcessRecord> udpTableRecords = new List<UdpProcessRecord>();

            // Getting the size of UDP table, that is returned in 'bufferSize' variable.
            uint result = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true,
                AF_INET, UdpTableClass.UDP_TABLE_OWNER_PID);

            // Allocating memory from the unmanaged memory of the process by using the
            // specified number of bytes in 'bufferSize' variable.
            IntPtr udpTableRecordPtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                // The size of the table returned in 'bufferSize' variable in previous
                // call must be used in this subsequent call to 'GetExtendedUdpTable'
                // function in order to successfully retrieve the table.
                result = GetExtendedUdpTable(udpTableRecordPtr, ref bufferSize, true,
                    AF_INET, UdpTableClass.UDP_TABLE_OWNER_PID);

                // Non-zero value represent the function 'GetExtendedUdpTable' failed,
                // hence empty list is returned to the caller function.
                if (result != 0)
                    return new List<UdpProcessRecord>();

                // Marshals data from an unmanaged block of memory to a newly allocated
                // managed object 'udpRecordsTable' of type 'MIB_UDPTABLE_OWNER_PID'
                // to get number of entries of the specified TCP table structure.
                MIB_UDPTABLE_OWNER_PID udpRecordsTable = (MIB_UDPTABLE_OWNER_PID)
                    Marshal.PtrToStructure(udpTableRecordPtr, typeof(MIB_UDPTABLE_OWNER_PID));
                IntPtr tableRowPtr = (IntPtr)((long)udpTableRecordPtr +
                    Marshal.SizeOf(udpRecordsTable.dwNumEntries));

                // Reading and parsing the UDP records one by one from the table and
                // storing them in a list of 'UdpProcessRecord' structure type objects.
                for (int i = 0; i < udpRecordsTable.dwNumEntries; i++)
                {
                    MIB_UDPROW_OWNER_PID udpRow = (MIB_UDPROW_OWNER_PID)
                        Marshal.PtrToStructure(tableRowPtr, typeof(MIB_UDPROW_OWNER_PID));
                    udpTableRecords.Add(new UdpProcessRecord(new IPAddress(udpRow.localAddr),
                        BitConverter.ToUInt16(new byte[2] { udpRow.localPort[1],
                            udpRow.localPort[0] }, 0), udpRow.owningPid));
                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(udpRow));
                }
            }
            catch (OutOfMemoryException outOfMemoryException)
            {
                //MessageBox.Show(outOfMemoryException.Message, "Out Of Memory",
                //    MessageBoxButtons.OK, MessageBoxIcon.Stop);
            }
            catch (Exception exception)
            {
                //MessageBox.Show(exception.Message, "Exception",
                //    MessageBoxButtons.OK, MessageBoxIcon.Stop);
            }
            finally
            {
                Marshal.FreeHGlobal(udpTableRecordPtr);
            }
            return udpTableRecords != null ? udpTableRecords.Distinct()
                .ToList<UdpProcessRecord>() : new List<UdpProcessRecord>();
        }

        private const int WSADESCRIPTION_LEN = 256;

        private const int WSASYSSTATUS_LEN = 128;

        [StructLayout(LayoutKind.Sequential)]
        public struct WSAData
        {
            public short wVersion;
            public short wHighVersion;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WSADESCRIPTION_LEN + 1)]
            public string szDescription;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WSASYSSTATUS_LEN + 1)]
            public string wSystemStatus;
            [Obsolete("Ignored when wVersionRequested >= 2.0")]
            public ushort wMaxSockets;
            [Obsolete("Ignored when wVersionRequested >= 2.0")]
            public ushort wMaxUdpDg;
            public IntPtr dwVendorInfo;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct Servent
        {
            public string s_name;
            public IntPtr s_aliases;
            public short s_port;
            public string s_proto;
        }

        private static ushort MakeWord(byte low, byte high)
        {

            return (ushort)((ushort)(high << 8) | low);
        }

        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
        private static extern int WSAStartup(ushort wVersionRequested, ref WSAData wsaData);
        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
        private static extern int WSACleanup();
        [DllImport("ws2_32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr getservbyname(string name, string proto);
        [DllImport("ws2_32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr getservbyport(short port, string proto);

        public static string GetServiceByPort(short port, Protocol protocol, bool throwException = false)
        {

            WSAData wsaData = new WSAData();
            if (WSAStartup(MakeWord(2, 2), ref wsaData) != 0)
            {
                if (throwException == true)
                {
                    throw new Win32Exception(string.Format("WSAStartup {0}", Marshal.GetLastWin32Error()));
                }
                else
                {
                    return string.Empty;
                }
            }
            try
            {
                short netport = Convert.ToInt16(IPAddress.HostToNetworkOrder(port));
                IntPtr result = getservbyport(netport, protocol.ToString());
                if (IntPtr.Zero == result)
                {
                    if (throwException == true)
                    {
                        throw new Win32Exception(string.Format("Could not resolve service for port {0} {1}", port, Marshal.GetLastWin32Error()));
                    }
                    else
                    {
                        return string.Empty;
                    }
                }
                Servent srvent = (Servent)Marshal.PtrToStructure(result, typeof(Servent));
                return srvent.s_name; ;
            }
            finally
            {
                WSACleanup();
            }
        }


        public static short GetServiceByName(string service, Protocol protocol, bool throwException = false)
        {

            WSAData wsaData = new WSAData();
            if (WSAStartup(MakeWord(2, 2), ref wsaData) != 0)
            {
                if (throwException == true)
                {
                    throw new Win32Exception(string.Format("WSAStartup {0}", Marshal.GetLastWin32Error()));
                }
                else
                {
                    return -1;
                }
            }
            try
            {
                IntPtr result = getservbyname(service, protocol.ToString());
                if (IntPtr.Zero == result)
                {
                    if (throwException == true)
                    {
                        throw new Win32Exception(string.Format("Could not resolve port for service {0} {1}", service, Marshal.GetLastWin32Error()));
                    }
                    else
                    {
                        return -1;
                    }
                }
                Servent srvent = (Servent)Marshal.PtrToStructure(result, typeof(Servent));
                return Convert.ToInt16(IPAddress.NetworkToHostOrder(srvent.s_port));
            }
            finally
            {
                WSACleanup();
            }
        }

        static void Main(string[] args)
        {
            List<UdpProcessRecord> udpConnections = GetAllUdpConnections();
            List<TcpProcessRecord> tcpConnections = GetAllTcpConnections();

            Console.WriteLine("Protocol\tLocalAddress\tLocalPort\tLocalServiceName\tRemoteAddress\tRemotePort\tRemoteServiceName\tStatus\tPID\tProcess");

            foreach (UdpProcessRecord udpRecord in udpConnections)
            {
                Console.WriteLine("{0}\t{1}\t{2}\t{3}\t\t\t\t\t{4}\t{5}", Protocol.udp.ToString(), udpRecord.LocalAddress, udpRecord.LocalPort, GetServiceByPort((short)udpRecord.LocalPort, Protocol.udp), udpRecord.ProcessId, udpRecord.ProcessName);
            }
            foreach (TcpProcessRecord tcpRecord in tcpConnections)
            {
                Console.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t{8}\t{9}", Protocol.tcp.ToString(), tcpRecord.LocalAddress, tcpRecord.LocalPort, GetServiceByPort((short)tcpRecord.LocalPort, Protocol.tcp), tcpRecord.RemoteAddress, tcpRecord.RemotePort, GetServiceByPort((short)tcpRecord.RemotePort, Protocol.tcp), tcpRecord.State, tcpRecord.ProcessId, tcpRecord.ProcessName);
            }
        }
    }
}

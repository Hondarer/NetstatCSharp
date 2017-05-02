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
    public class Program
    {
        /// <summary>
        /// Enum for protocol types.
        /// </summary>
        public enum Protocol
        {
            /// <summary>
            /// TCP.
            /// </summary>
            tcp,

            /// <summary>
            /// UDP.
            /// </summary>
            udp
        }

        /// <summary>
        /// Enum to define the set of values used to indicate the type of table returned by 
        /// calls made to the function <see cref="GetExtendedTcpTable"/>.
        /// </summary>
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

        /// <summary>
        /// Enum to define the set of values used to indicate the type of table returned by calls
        /// made to the function <see cref="GetExtendedUdpTable"/>.
        /// </summary>
        public enum UdpTableClass
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        /// <summary>
        /// Enum for different possible states of TCP connection.
        /// </summary>
        public enum MibTcpState
        {
            /// <summary>
            /// The TCP connection is in the CLOSED state that represents no connection state at all.
            /// </summary>
            CLOSED = 1,

            /// <summary>
            /// The TCP connection is in the LISTEN state waiting for a connection request from any remote TCP and port.
            /// </summary>
            LISTENING = 2,

            /// <summary>
            /// The TCP connection is in the SYN-SENT state waiting for a matching connection request after having sent a connection request (SYN packet).
            /// </summary>
            SYN_SENT = 3,

            /// <summary>
            /// The TCP connection is in the SYN-RECEIVED state waiting for a confirming connection request acknowledgment after having both received and sent a connection request (SYN packet).
            /// </summary>
            SYN_RCVD = 4,

            /// <summary>
            /// The TCP connection is in the ESTABLISHED state that represents an open connection, data received can be delivered to the user. This is the normal state for the data transfer phase of the TCP connection.
            /// </summary>
            ESTABLISHED = 5,

            /// <summary>
            /// The TCP connection is FIN-WAIT-1 state waiting for a connection termination request from the remote TCP, or an acknowledgment of the connection termination request previously sent.
            /// </summary>
            FIN_WAIT1 = 6,

            /// <summary>
            /// The TCP connection is FIN-WAIT-2 state waiting for a connection termination request from the remote TCP.
            /// </summary>
            FIN_WAIT2 = 7,

            /// <summary>
            /// The TCP connection is in the CLOSE-WAIT state waiting for a connection termination request from the local user.
            /// </summary>
            CLOSE_WAIT = 8,

            /// <summary>
            /// The TCP connection is in the CLOSING state waiting for a connection termination request acknowledgment from the remote TCP.
            /// </summary>
            CLOSING = 9,

            /// <summary>
            /// The TCP connection is in the LAST-ACK state waiting for an acknowledgment of the connection termination request previously sent to the remote TCP (which includes an acknowledgment of its connection termination request).
            /// </summary>
            LAST_ACK = 10,

            /// <summary>
            /// The TCP connection is in the TIME-WAIT state waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connection termination request.
            /// </summary>
            TIME_WAIT = 11,

            /// <summary>
            /// The TCP connection is in the delete TCB state that represents the deletion of the Transmission Control Block (TCB), a data structure used to maintain information on each TCP entry.
            /// </summary>
            DELETE_TCB = 12,

            /// <summary>
            /// Default value.
            /// </summary>
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
            /// <summary>
            /// The state of the TCP connection.
            /// </summary>
            public MibTcpState state;

            /// <summary>
            /// The local IPv4 address for the TCP connection on the local computer.
            /// </summary>
            public uint localAddr;

            /// <summary>
            /// The local port number in network byte order for the TCP connection on the local computer.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;

            /// <summary>
            /// The IPv4 address for the TCP connection on the remote computer.
            /// </summary>
            public uint remoteAddr;

            /// <summary>
            /// The remote port number in network byte order for the TCP connection on the remote computer.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] remotePort;

            /// <summary>
            /// The PID of the process that issued a context bind for this TCP connection.
            /// </summary>
            public uint owningPid;
        }

        /// <summary>
        /// The structure contains information that describes an IPv6 TCP connection with 
        /// IPv6 addresses, ports used by the TCP connection, and the specific process ID
        /// (PID) associated with connection.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6ROW_OWNER_PID
        {
            /// <summary>
            /// The IPv6 address for the local endpoint of the TCP connection on the local computer.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;

            /// <summary>
            /// The scope ID in network byte order for the local IPv6 address.
            /// </summary>
            public uint localScopeId;

            /// <summary>
            /// The port number in network byte order for the local endpoint of the TCP connection on the local computer.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;

            /// <summary>
            /// The IPv6 address of the remote endpoint of the TCP connection on the remote computer.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] remoteAddr;

            /// <summary>
            /// The scope ID in network byte order for the remote IPv6 address.
            /// </summary>
            public uint remoteScopeId;

            /// <summary>
            /// The port number in network byte order for the remote endpoint of the TCP connection on the remote computer.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] remotePort;

            /// <summary>
            /// The state of the TCP connection.
            /// </summary>
            public MibTcpState state;

            /// <summary>
            /// The PID of the process that issued a context bind for this TCP connection.
            /// </summary>
            public uint owningPid;
        }

        /// <summary>
        /// The structure contains an entry from the User Datagram Protocol (UDP) listener
        /// table for IPv4 on the local computer. The entry also includes the process ID
        /// (PID) that issued the call to the bind function for the UDP endpoint.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            /// <summary>
            /// The IPv4 address of the UDP endpoint on the local computer.
            /// </summary>
            public uint localAddr;

            /// <summary>
            /// The port number of the UDP endpoint on the local computer. This member is stored in network byte order.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;

            /// <summary>
            /// The PID of the process that issued the call to the bind function for the UDP endpoint. This member is set to 0 when the PID is unavailable.
            /// </summary>
            public uint owningPid;
        }

        /// <summary>
        /// The structure contains an entry from the User Datagram Protocol (UDP) listener
        /// table for IPv6 on the local computer. The entry also includes the process ID
        /// (PID) that issued the call to the bind function for the UDP endpoint.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDP6ROW_OWNER_PID
        {
            /// <summary>
            /// The IPv6 address of the UDP endpoint on the local computer.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;

            /// <summary>
            /// The scope ID in network byte order for the local IPv6 address.
            /// </summary>
            public uint localScopeId;

            /// <summary>
            /// The port number of the UDP endpoint on the local computer. This member is stored in network byte order.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] localPort;

            /// <summary>
            /// The PID of the process that issued the call to the bind function for the UDP endpoint. This member is set to 0 when the PID is unavailable.
            /// </summary>
            public uint owningPid;
        }

        /// <summary>
        /// The structure contains a table of process IDs (PIDs) and the IPv4 TCP links that 
        /// are context bound to these PIDs.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            /// <summary>
            /// The number of <see cref="MIB_TCPROW_OWNER_PID"/> elements in the table.
            /// </summary>
            public uint dwNumEntries;

            /// <summary>
            /// An array of <see cref="MIB_TCPROW_OWNER_PID"/> structures returned by a call to <see cref="GetExtendedTcpTable"/>.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public MIB_TCPROW_OWNER_PID[] table;
        }

        /// <summary>
        /// The structure contains a table of process IDs (PIDs) and the IPv6 TCP links that
        /// are context bound to these PIDs.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6TABLE_OWNER_PID
        {
            /// <summary>
            /// The number of <see cref="MIB_TCP6ROW_OWNER_PID"/> elements in the table.
            /// </summary>
            public uint dwNumEntries;

            /// <summary>
            /// An array of <see cref="MIB_TCP6ROW_OWNER_PID"/> structures returned by a call to <see cref="GetExtendedTcpTable"/>.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public MIB_TCP6ROW_OWNER_PID[] table;
        }

        /// <summary>
        /// The structure contains the User Datagram Protocol (UDP) listener table for IPv4
        /// on the local computer. The table also includes the process ID (PID) that issued
        /// the call to the bind function for each UDP endpoint.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPTABLE_OWNER_PID
        {
            /// <summary>
            /// The number of <see cref="MIB_UDPROW_OWNER_PID"/> elements in table.
            /// </summary>
            public uint dwNumEntries;

            /// <summary>
            /// An array of <see cref="MIB_UDPROW_OWNER_PID"/> structures returned by a call to <see cref="GetExtendedUdpTable"/>.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public MIB_UDPROW_OWNER_PID[] table;
        }

        /// <summary>
        /// The structure contains the User Datagram Protocol (UDP) listener table for IPv6
        /// on the local computer. The table also includes the process ID (PID) that issued
        /// the call to the bind function for each UDP endpoint.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDP6TABLE_OWNER_PID
        {
            /// <summary>
            /// The number of <see cref="MIB_UDP6ROW_OWNER_PID"/> elements in table.
            /// </summary>
            public uint dwNumEntries;

            /// <summary>
            /// An array of <see cref="MIB_UDP6ROW_OWNER_PID"/> structures returned by a call to <see cref="GetExtendedUdpTable"/>.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public MIB_UDP6ROW_OWNER_PID[] table;
        }

        /// <summary>
        /// This class provides access an TCP connection addresses and ports and its
        /// associated Process IDs and names.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public class TcpProcessRecord
        {
            public IPAddress LocalAddress { get; set; }
            public long LocalScopeId { get; set; }
            public ushort LocalPort { get; set; }
            public IPAddress RemoteAddress { get; set; }
            public long RemoteScopeId { get; set; }
            public ushort RemotePort { get; set; }
            public MibTcpState State { get; set; }
            public uint ProcessId { get; set; }
            public string ProcessName { get; set; }

            public TcpProcessRecord(IPAddress localIp, IPAddress remoteIp, ushort localPort, ushort remotePort, uint pId, MibTcpState state)
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
                    ProcessName = Process.GetProcessById((int)ProcessId).ProcessName;
                }
            }
        }

        /// <summary>
        /// This class provides access an UDP connection addresses and ports and its
        /// associated Process IDs and names.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public class UdpProcessRecord
        {
            public IPAddress LocalAddress { get; set; }
            public uint LocalPort { get; set; }
            public uint ProcessId { get; set; }
            public string ProcessName { get; set; }

            public UdpProcessRecord(IPAddress localAddress, uint localPort, uint pId)
            {
                LocalAddress = localAddress;
                LocalPort = localPort;
                ProcessId = pId;
                // Getting the process name associated with a process id.
                if (Process.GetProcesses().Any(process => process.Id == pId))
                {
                    ProcessName = Process.GetProcessById((int)ProcessId).ProcessName;
                }
            }
        }

        /// <summary>
        /// IPv4 を表します。
        /// </summary>
        public const int AF_INET = 2;    // IP_v4 = System.Net.Sockets.AddressFamily.InterNetwork

        /// <summary>
        /// IPv6 を表します。
        /// </summary>
        public const int AF_INET6 = 23;  // IP_v6 = System.Net.Sockets.AddressFamily.InterNetworkV6

        // The GetExtendedTcpTable function retrieves a table that contains a list of
        // TCP endpoints available to the application. Decorating the function with
        // DllImport attribute indicates that the attributed method is exposed by an
        // unmanaged dynamic-link library 'iphlpapi.dll' as a static entry point.
        [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

        /// <summary>
        /// Retrieves a table that contains a list of UDP endpoints available to the application.
        /// </summary>
        /// <param name="pUdpTable"></param>
        /// <param name="pdwSize"></param>
        /// <param name="bOrder"></param>
        /// <param name="ulAf"></param>
        /// <param name="tableClass"></param>
        /// <param name="reserved"></param>
        /// <returns>
        /// If the call is successful, the value <c>0</c> is returned.
        /// If the function fails, the return value is one of the following error codes.
        /// </returns>
        [DllImport("iphlpapi.dll")]
        public static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved = 0);

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
        public static List<TcpProcessRecord> GetAllTcpv4Connections()
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
        public static List<TcpProcessRecord> GetAllTcpv6Connections()
        {
            int bufferSize = 0;
            List<TcpProcessRecord> tcpTableRecords = new List<TcpProcessRecord>();

            // Getting the size of TCP table, that is returned in 'bufferSize' variable.
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6,
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
                    AF_INET6, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

                // Non-zero value represent the function 'GetExtendedTcpTable' failed,
                // hence empty list is returned to the caller function.
                if (result != 0)
                    return new List<TcpProcessRecord>();

                // Marshals data from an unmanaged block of memory to a newly allocated
                // managed object 'tcpRecordsTable' of type 'MIB_TCPTABLE_OWNER_PID'
                // to get number of entries of the specified TCP table structure.
                MIB_TCP6TABLE_OWNER_PID tcpRecordsTable = (MIB_TCP6TABLE_OWNER_PID)
                                        Marshal.PtrToStructure(tcpTableRecordsPtr,
                                        typeof(MIB_TCP6TABLE_OWNER_PID));
                IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr +
                                        Marshal.SizeOf(tcpRecordsTable.dwNumEntries));

                // Reading and parsing the TCP records one by one from the table and
                // storing them in a list of 'TcpProcessRecord' structure type objects.
                for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++)
                {
                    MIB_TCP6ROW_OWNER_PID tcpRow = (MIB_TCP6ROW_OWNER_PID)Marshal.
                        PtrToStructure(tableRowPtr, typeof(MIB_TCP6ROW_OWNER_PID));
                    tcpTableRecords.Add(new TcpProcessRecord(
                                          new IPAddress(tcpRow.localAddr, tcpRow.localScopeId),
                                          new IPAddress(tcpRow.remoteAddr, tcpRow.localScopeId),
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
        public static List<UdpProcessRecord> GetAllUdpv4Connections()
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

        /// <summary>
        /// IPv6 の UDP 接続を列挙したリストを返します。
        /// </summary>
        /// <param name="throwException">例外を発生させるかどうか。省略可能です。既定値は <c>false</c> です。</param>
        /// <returns>UDP 接続のリスト。<see para="throwException"/> が <c>false</c> の場合に失敗した場合は、<c>null</c> を返します。</returns>
        /// <exception cref="Exception"><see para="throwException"/> が <c>true</c> の場合に API の呼び出しに失敗しました。</exception>
        public static List<UdpProcessRecord> GetAllUdpv6Connections(bool throwException = false)
        {
            int bufferSize = 0;
            List<UdpProcessRecord> udpTableRecords = new List<UdpProcessRecord>();

            // Getting the size of UDP table, that is returned in 'bufferSize' variable.
            uint result = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6, UdpTableClass.UDP_TABLE_OWNER_PID);
            // ここでの result は必ず ERROR_INSUFFICIENT_BUFFER(0x0000007a) なので見ない

            // Allocating memory from the unmanaged memory of the process by using the
            // specified number of bytes in 'bufferSize' variable.
            IntPtr udpTableRecordPtr = Marshal.AllocCoTaskMem(bufferSize);

            try
            {
                // The size of the table returned in 'bufferSize' variable in previous
                // call must be used in this subsequent call to 'GetExtendedUdpTable'
                // function in order to successfully retrieve the table.
                result = GetExtendedUdpTable(udpTableRecordPtr, ref bufferSize, true, AF_INET6, UdpTableClass.UDP_TABLE_OWNER_PID);

                // Non-zero value represent the function 'GetExtendedUdpTable' failed,
                // hence empty list is returned to the caller function.
                if (result != 0)
                {
                    if (throwException == true)
                    {
                        throw new Win32Exception("GetExtendedUdpTable");
                    }
                    else
                    {
                        return null;
                    }
                }

                // Marshals data from an unmanaged block of memory to a newly allocated
                // managed object 'udpRecordsTable' of type 'MIB_UDPTABLE_OWNER_PID'
                // to get number of entries of the specified TCP table structure.
                MIB_UDP6TABLE_OWNER_PID udpRecordsTable = (MIB_UDP6TABLE_OWNER_PID)Marshal.PtrToStructure(udpTableRecordPtr, typeof(MIB_UDP6TABLE_OWNER_PID));
                IntPtr tableRowPtr = (IntPtr)((long)udpTableRecordPtr + Marshal.SizeOf(udpRecordsTable.dwNumEntries));

                // Reading and parsing the UDP records one by one from the table and
                // storing them in a list of 'UdpProcessRecord' structure type objects.
                for (int i = 0; i < udpRecordsTable.dwNumEntries; i++)
                {
                    MIB_UDP6ROW_OWNER_PID udpRow = (MIB_UDP6ROW_OWNER_PID)Marshal.PtrToStructure(tableRowPtr, typeof(MIB_UDP6ROW_OWNER_PID));
                    udpTableRecords.Add(
                        new UdpProcessRecord(
                            new IPAddress(
                                udpRow.localAddr, 
                                udpRow.localScopeId),
                                BitConverter.ToUInt16(new byte[] { udpRow.localPort[1], udpRow.localPort[0] }, 0),
                                udpRow.owningPid));

                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(udpRow));
                }
            }
            catch (Exception)
            {
                if (throwException == true)
                {
                    throw;
                }
                else
                {
                    return null;
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(udpTableRecordPtr);
            }

            return udpTableRecords;
        }

        /// <summary>
        /// Length of description of the Windows Sockets implementation.
        /// </summary>
        private const int WSADESCRIPTION_LEN = 256;

        /// <summary>
        /// Length of status or configuration information.
        /// </summary>
        private const int WSASYSSTATUS_LEN = 128;

        /// <summary>
        /// Contains information about the Windows Sockets implementation.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct WSAData
        {
            /// <summary>
            /// The version of the Windows Sockets specification that the Ws2_32.dll expects the caller to use.
            /// </summary>
            public short wVersion;

            /// <summary>
            /// The highest version of the Windows Sockets specification that the Ws2_32.dll can support.
            /// </summary>
            public short wHighVersion;

            /// <summary>
            /// String into which the Ws2_32.dll copies a description of the Windows Sockets implementation.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WSADESCRIPTION_LEN + 1)]
            public string szDescription;

            /// <summary>
            /// String into which the Ws2_32.dll copies relevant status or configuration information.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WSASYSSTATUS_LEN + 1)]
            public string wSystemStatus;

            /// <summary>
            /// The maximum number of sockets that may be opened.
            /// </summary>
            [Obsolete("Ignored when wVersionRequested >= 2.0")]
            public ushort wMaxSockets;

            /// <summary>
            /// The maximum datagram message size.
            /// </summary>
            [Obsolete("Ignored when wVersionRequested >= 2.0")]
            public ushort wMaxUdpDg;

            /// <summary>
            /// A pointer to vendor-specific information. This member should be ignored for Windows Sockets version 2 and later.
            /// </summary>
            [Obsolete("Ignored when wVersionRequested >= 2.0")]
            public IntPtr dwVendorInfo;
        }

        /// <summary>
        /// Used to store or return the name and service number for a given service name.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct Servent
        {
            /// <summary>
            /// The official name of the service.
            /// </summary>
            public string s_name;

            /// <summary>
            /// array of alternate names.
            /// </summary>
            public IntPtr s_aliases;

            /// <summary>
            /// The port number at which the service can be contacted. Port numbers are returned in network byte order.
            /// </summary>
            public short s_port;

            /// <summary>
            /// The name of the protocol to use when contacting the service.
            /// </summary>
            public string s_proto;
        }

        /// <summary>
        /// ネットワーク バイト オーダーのワードを生成します。
        /// </summary>
        /// <param name="low">下位バイト。</param>
        /// <param name="high">上位バイト。</param>
        /// <returns>ネットワーク バイト オーダーのワード。</returns>
        private static ushort MakeWord(byte low, byte high)
        {
            return (ushort)((ushort)(high << 8) | low);
        }

        /// <summary>
        /// 利用する Winsock のメジャーバージョンを表します。
        /// </summary>
        private const int WINSOCK_MAJOR_VERSION = 2;

        /// <summary>
        /// 利用する Winsock のマイナーバージョンを表します。
        /// </summary>
        private const int WINSOCK_MINOR_VERSION = 2;

        /// <summary>
        /// Initiates use of the Winsock DLL by a process.
        /// </summary>
        /// <param name="wVersionRequested">The highest version of Windows Sockets specification that the caller can use.</param>
        /// <param name="wsaData">A refernce to the <see cref="WSAData"/> data structure that is to receive details of the Windows Sockets implementation.</param>
        /// <returns>
        /// If successful, the function returns zero. Otherwise, it returns one of the error codes listed below.
        /// </returns>
        [DllImport("ws2_32.dll", SetLastError = true)]
        public static extern int WSAStartup(ushort wVersionRequested, ref WSAData wsaData);

        /// <summary>
        /// Terminates use of the Winsock 2 DLL (Ws2_32.dll).
        /// </summary>
        /// <returns>The return value is zero if the operation was successful. Otherwise, the value SOCKET_ERROR is returned.</returns>
        [DllImport("ws2_32.dll", SetLastError = true)]
        public static extern int WSACleanup();

        /// <summary>
        /// Retrieves service information corresponding to a service name and protocol.
        /// </summary>
        /// <param name="name">service name.</param>
        /// <param name="proto">protocol name.</param>
        /// <returns>If no error occurs, getservbyname returns a pointer to the <see cref="Servent"/> structure. Otherwise, it returns a <see cref="IntPtr.Zero"/>.</returns>
        [DllImport("ws2_32.dll", SetLastError = true)]
        private static extern IntPtr getservbyname(string name, string proto);

        /// <summary>
        /// Retrieves service information corresponding to a port and protocol.
        /// </summary>
        /// <param name="port">Port for a service, in network byte order.</param>
        /// <param name="proto">protocol name.</param>
        /// <returns>If no error occurs, getservbyname returns a pointer to the <see cref="Servent"/> structure. Otherwise, it returns a <see cref="IntPtr.Zero"/>.</returns>
        [DllImport("ws2_32.dll", SetLastError = true)]
        private static extern IntPtr getservbyport(short port, string proto);

        /// <summary>
        /// ポート番号とプロトコルから、サービス名を取得します。
        /// </summary>
        /// <param name="port">ポート番号。</param>
        /// <param name="protocol">プロトコル。</param>
        /// <param name="throwException">例外を発生させるかどうか。省略可能です。既定値は <c>false</c> です。</param>
        /// <returns>サービス名。<see para="throwException"/> が <c>false</c> の場合に失敗した場合は、<c>null</c> を返します。</returns>
        /// <exception cref="Win32Exception"><see para="throwException"/> が <c>true</c> の場合に API の呼び出しに失敗しました。</exception>
        public static string GetServiceByPort(short port, Protocol protocol, bool throwException = false)
        {

            WSAData wsaData = new WSAData();
            if (WSAStartup(MakeWord(WINSOCK_MAJOR_VERSION, WINSOCK_MINOR_VERSION), ref wsaData) != 0)
            {
                if (throwException == true)
                {
                    throw new Win32Exception(string.Format("WSAStartup {0}", Marshal.GetLastWin32Error()));
                }
                else
                {
                    return null;
                }
            }
            try
            {
                short netport = Convert.ToInt16(IPAddress.HostToNetworkOrder(port));
                IntPtr result = getservbyport(netport, protocol.ToString());
                if (result == IntPtr.Zero)
                {
                    if (throwException == true)
                    {
                        throw new Win32Exception(string.Format("Could not resolve service for port {0} {1}", port, Marshal.GetLastWin32Error()));
                    }
                    else
                    {
                        return null;
                    }
                }
                Servent srvent = (Servent)Marshal.PtrToStructure(result, typeof(Servent));
                return srvent.s_name;
            }
            finally
            {
                WSACleanup();
            }
        }

        /// <summary>
        /// サービス名とプロトコルから、ポート番号を取得します。
        /// </summary>
        /// <param name="service">サービス名。</param>
        /// <param name="protocol">プロトコル。</param>
        /// <param name="throwException">例外を発生させるかどうか。省略可能です。既定値は <c>false</c> です。</param>
        /// <returns>ポート番号。<see para="throwException"/> が <c>false</c> の場合に失敗した場合は、<c>-1</c> を返します。</returns>
        /// <exception cref="Win32Exception"><see para="throwException"/> が <c>true</c> の場合に API の呼び出しに失敗しました。</exception>
        public static short GetServiceByName(string service, Protocol protocol, bool throwException = false)
        {
            WSAData wsaData = new WSAData();
            if (WSAStartup(MakeWord(WINSOCK_MAJOR_VERSION, WINSOCK_MINOR_VERSION), ref wsaData) != 0)
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
                if (result == IntPtr.Zero)
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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            List<TcpProcessRecord> tcpv4Connections = GetAllTcpv4Connections();
            List<TcpProcessRecord> tcpv6Connections = GetAllTcpv6Connections();
            List<UdpProcessRecord> udpv4Connections = GetAllUdpv4Connections();
            List<UdpProcessRecord> udpv6Connections = GetAllUdpv6Connections();

            Console.WriteLine("\"Protocol\"\t\"LocalAddress\"\t\"LocalPort\"\t\"LocalServiceName\"\t\"RemoteAddress\"\t\"RemotePort\"\t\"RemoteServiceName\"\t\"Status\"\t\"PID\"\t\"Process\"");

            if (tcpv4Connections != null)
            {
                foreach (TcpProcessRecord tcpRecord in tcpv4Connections)
                {
                    Console.WriteLine("\"{0}\"\t\"{1}\"\t{2}\t\"{3}\"\t\"{4}\"\t{5}\t\"{6}\"\t\"{7}\"\t{8}\t\"{9}\"", Protocol.tcp.ToString(), tcpRecord.LocalAddress, tcpRecord.LocalPort, GetServiceByPort((short)tcpRecord.LocalPort, Protocol.tcp), tcpRecord.RemoteAddress, tcpRecord.RemotePort, GetServiceByPort((short)tcpRecord.RemotePort, Protocol.tcp), tcpRecord.State, tcpRecord.ProcessId, tcpRecord.ProcessName);
                }
            }
            if (tcpv6Connections != null)
            {
                foreach (TcpProcessRecord tcpv6Record in tcpv6Connections)
                {
                    Console.WriteLine("\"{0}\"\t\"[{1}]\"\t{2}\t\"{3}\"\t\"[{4}]\"\t{5}\t\"{6}\"\t\"{7}\"\t{8}\t\"{9}\"", Protocol.tcp.ToString(), tcpv6Record.LocalAddress, tcpv6Record.LocalPort, GetServiceByPort((short)tcpv6Record.LocalPort, Protocol.tcp), tcpv6Record.RemoteAddress, tcpv6Record.RemotePort, GetServiceByPort((short)tcpv6Record.RemotePort, Protocol.tcp), tcpv6Record.State, tcpv6Record.ProcessId, tcpv6Record.ProcessName);
                }
            }
            if (udpv4Connections != null)
            {
                foreach (UdpProcessRecord udpRecord in udpv4Connections)
                {
                    Console.WriteLine("\"{0}\"\t\"{1}\"\t{2}\t\"{3}\"\t\"*\"\t*\t\"*\"\t\"\"\t{4}\t\"{5}\"", Protocol.udp.ToString(), udpRecord.LocalAddress, udpRecord.LocalPort, GetServiceByPort((short)udpRecord.LocalPort, Protocol.udp), udpRecord.ProcessId, udpRecord.ProcessName);
                }
            }
            if (udpv6Connections != null)
            {
                foreach (UdpProcessRecord udpv6Record in udpv6Connections)
                {
                    Console.WriteLine("\"{0}\"\t\"[{1}]\"\t{2}\t\"{3}\"\t\"*\"\t*\t\"*\"\t\"\"\t{4}\t\"{5}\"", Protocol.udp.ToString(), udpv6Record.LocalAddress, udpv6Record.LocalPort, GetServiceByPort((short)udpv6Record.LocalPort, Protocol.udp), udpv6Record.ProcessId, udpv6Record.ProcessName);
                }
            }
        }
    }
}

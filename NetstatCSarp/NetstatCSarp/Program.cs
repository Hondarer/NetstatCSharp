// Based on 'C# Sample to list all the active TCP and UDP connections using Windows Form appl' by OneCode.
// https://code.msdn.microsoft.com/windowsdesktop/C-Sample-to-list-all-the-4817b58f

// http://stackoverflow.com/questions/13246099/using-c-sharp-to-reference-a-port-number-to-service-name

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Linq;

namespace NetstatCSharp
{
    /// <summary>
    /// 
    /// </summary>
    public class Program
    {
        #region ネットワーク関連

        /// <summary>
        /// 利用する Winsock のメジャーバージョンを表します。
        /// </summary>
        private const int WINSOCK_MAJOR_VERSION = 2;

        /// <summary>
        /// 利用する Winsock のマイナーバージョンを表します。
        /// </summary>
        private const int WINSOCK_MINOR_VERSION = 2;

        /// <summary>
        /// Length of description of the Windows Sockets implementation.
        /// </summary>
        private const int WSADESCRIPTION_LEN = 256;

        /// <summary>
        /// Length of status or configuration information.
        /// </summary>
        private const int WSASYSSTATUS_LEN = 128;

        /// <summary>
        /// アドレス体系を表します。
        /// </summary>
        public enum AddressFamily : int
        {
            /// <summary>
            /// IPv4。
            /// </summary>
            AF_INET = 2,

            /// <summary>
            /// IPv6。
            /// </summary>
            AF_INET6 = 23
        }

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
            /// <summary>
            /// A MIB_TCPTABLE table that contains all listening (receiving only) TCP endpoints on the local computer is returned to the caller.
            /// </summary>
            TCP_TABLE_BASIC_LISTENER,

            /// <summary>
            /// A MIB_TCPTABLE table that contains all connected TCP endpoints on the local computer is returned to the caller.
            /// </summary>
            TCP_TABLE_BASIC_CONNECTIONS,

            /// <summary>
            /// A MIB_TCPTABLE table that contains all TCP endpoints on the local computer is returned to the caller.
            /// </summary>
            TCP_TABLE_BASIC_ALL,

            /// <summary>
            /// A <see cref="MIB_TCPTABLE_OWNER_PID"/> or <see cref="MIB_TCP6TABLE_OWNER_PID"/> that contains all listening (receiving only) TCP endpoints on the local computer is returned to the caller.
            /// </summary>
            TCP_TABLE_OWNER_PID_LISTENER,

            /// <summary>
            /// A <see cref="MIB_TCPTABLE_OWNER_PID"/> or <see cref="MIB_TCP6TABLE_OWNER_PID"/> that structure that contains all connected TCP endpoints on the local computer is returned to the caller.
            /// </summary>
            TCP_TABLE_OWNER_PID_CONNECTIONS,

            /// <summary>
            /// A <see cref="MIB_TCPTABLE_OWNER_PID"/> or <see cref="MIB_TCP6TABLE_OWNER_PID"/> structure that contains all TCP endpoints on the local computer is returned to the caller.
            /// </summary>
            TCP_TABLE_OWNER_PID_ALL,

            /// <summary>
            /// A MIB_TCPTABLE_OWNER_MODULE or MIB_TCP6TABLE_OWNER_MODULE structure that contains all listening (receiving only) TCP endpoints on the local computer is returned to the caller.
            /// </summary>
            TCP_TABLE_OWNER_MODULE_LISTENER,

            /// <summary>
            /// A MIB_TCPTABLE_OWNER_MODULE or MIB_TCP6TABLE_OWNER_MODULE structure that contains all connected TCP endpoints on the local computer is returned to the caller.
            /// </summary>
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,

            /// <summary>
            /// A MIB_TCPTABLE_OWNER_MODULE or MIB_TCP6TABLE_OWNER_MODULE structure that contains all TCP endpoints on the local computer is returned to the caller.
            /// </summary>
            TCP_TABLE_OWNER_MODULE_ALL
        }

        /// <summary>
        /// Enum to define the set of values used to indicate the type of table returned by calls
        /// made to the function <see cref="GetExtendedUdpTable"/>.
        /// </summary>
        public enum UdpTableClass
        {
            /// <summary>
            /// A MIB_UDPTABLE structure that contains all UDP endpoints on the local computer is returned to the caller.
            /// </summary>
            UDP_TABLE_BASIC,

            /// <summary>
            /// A <see cref="MIB_UDPTABLE_OWNER_PID"/> or <see cref="MIB_UDP6TABLE_OWNER_PID"/> structure that contains all UDP endpoints on the local computer is returned to the caller.
            /// </summary>
            UDP_TABLE_OWNER_PID,

            /// <summary>
            /// A MIB_UDPTABLE_OWNER_MODULE or MIB_UDP6TABLE_OWNER_MODULE structure that contains all UDP endpoints on the local computer is returned to the caller.
            /// </summary>
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
        /// Retrieves a table that contains a list of TCP endpoints available to the application.
        /// </summary>
        /// <param name="pTcpTable">A pointer to the table structure that contains the filtered TCP endpoints available to the application.</param>
        /// <param name="pdwSize">The estimated size of the structure returned in <see para="pTcpTable"/>.</param>
        /// <param name="bOrder">A value that specifies whether the TCP connection table should be sorted.</param>
        /// <param name="ulAf">The version of IP used by the TCP endpoints.</param>
        /// <param name="tableClass">The type of the TCP table structure to retrieve.</param>
        /// <param name="reserved">Reserved. This value must be zero.</param>
        /// <returns>
        /// If the call is successful, the value <c>0</c> is returned.
        /// If the function fails, the return value is one of the following error codes.
        /// </returns>
        [DllImport("iphlpapi.dll")]
        public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, AddressFamily ulAf, TcpTableClass tableClass, uint reserved = 0);

        /// <summary>
        /// Retrieves a table that contains a list of UDP endpoints available to the application.
        /// </summary>
        /// <param name="pUdpTable">A pointer to the table structure that contains the filtered UDP endpoints available to the application.</param>
        /// <param name="pdwSize">The estimated size of the structure returned in <see para="pUdpTable"/>.</param>
        /// <param name="bOrder">A value that specifies whether the UDP endpoint table should be sorted.</param>
        /// <param name="ulAf">The version of IP used by the UDP endpoint.</param>
        /// <param name="tableClass">The type of the UDP table structure to retrieve.</param>
        /// <param name="reserved">Reserved. This value must be zero.</param>
        /// <returns>
        /// If the call is successful, the value <c>0</c> is returned.
        /// If the function fails, the return value is one of the following error codes.
        /// </returns>
        [DllImport("iphlpapi.dll")]
        public static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, AddressFamily ulAf, UdpTableClass tableClass, uint reserved = 0);

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

        #endregion

        /// <summary>
        /// 接続情報の基底機能を提供します。
        /// </summary>
        public class ProcessRecordBase
        {
            /// <summary>
            /// The PID of the process that issued the call to the bind function.
            /// </summary>
            public uint ProcessId { get; private set; }

            /// <summary>
            /// A process name that issued the call to the bind function for the UDP endpoint.
            /// </summary>
            public string ProcessName { get; private set; }

            /// <summary>
            /// PID を設定します。
            /// </summary>
            /// <param name="processId">PID。</param>
            /// <param name="pidToProcessName">PID と プロセス名の関係をキャッシュするディクショナリを指定します。<c>null</c> の場合はキャッシュを行いません。</param>
            protected void SetProcessId(uint processId, Dictionary<uint, string> pidToProcessName)
            {
                ProcessId = processId;
                if (ProcessId != 0)
                {
                    try
                    {
                        if (pidToProcessName != null)
                        {
                            if (pidToProcessName.ContainsKey(ProcessId) == true)
                            {
                                ProcessName = pidToProcessName[ProcessId];
                            }
                            else
                            {
                                ProcessName = Process.GetProcessById((int)ProcessId).ProcessName;
                                pidToProcessName.Add(ProcessId, ProcessName);
                            }
                        }
                        else
                        {
                            ProcessName = Process.GetProcessById((int)ProcessId).ProcessName;
                        }
                    }
                    catch
                    {
                        ProcessName = string.Empty;
                    }
                }
                else
                {
                    ProcessName = string.Empty;
                }
            }
        }

        /// <summary>
        /// This class provides access an TCP connection addresses and ports and its
        /// associated Process IDs and names.
        /// </summary>
        public class TcpProcessRecord : ProcessRecordBase
        {
            /// <summary>
            /// The local address for the TCP connection on the local computer.
            /// </summary>
            public IPAddress LocalAddress { get; private set; }

            /// <summary>
            /// The local port number for the TCP connection on the local computer.
            /// </summary>
            public ushort LocalPort { get; private set; }

            /// <summary>
            /// The address for the TCP connection on the remote computer.
            /// </summary>
            public IPAddress RemoteAddress { get; private set; }

            /// <summary>
            /// The remote port number for the TCP connection on the remote computer.
            /// </summary>
            public ushort RemotePort { get; private set; }

            /// <summary>
            /// The state of the TCP connection.
            /// </summary>
            public MibTcpState State { get; private set; }

            /// <summary>
            /// <see cref="TcpProcessRecord"/> の新しいインスタンスを初期化します。
            /// </summary>
            /// <param name="localIp">The local address for the TCP connection on the local computer.</param>
            /// <param name="remoteIp">The address for the TCP connection on the remote computer.</param>
            /// <param name="localPort">The local port number for the TCP connection on the local computer.</param>
            /// <param name="remotePort">The remote port number for the TCP connection on the remote computer.</param>
            /// <param name="pId">The PID of the process that issued a context bind for this TCP connection.</param>
            /// <param name="state">The state of the TCP connection.</param>
            /// <param name="pidToProcessName">PID と プロセス名の関係をキャッシュするディクショナリを指定します。<c>null</c> の場合はキャッシュを行いません。省略可能です。既定値は <c>null</c> です。</param>
            public TcpProcessRecord(IPAddress localIp, IPAddress remoteIp, ushort localPort, ushort remotePort, uint pId, MibTcpState state, Dictionary<uint, string> pidToProcessName = null)
            {
                LocalAddress = localIp;
                RemoteAddress = remoteIp;
                LocalPort = localPort;
                RemotePort = remotePort;
                State = state;
                SetProcessId(pId, pidToProcessName);
            }
        }

        /// <summary>
        /// This class provides access an UDP endpoint addresses and ports and its
        /// associated Process IDs and names.
        /// </summary>
        public class UdpProcessRecord : ProcessRecordBase
        {
            /// <summary>
            /// The address of the UDP endpoint on the local computer.
            /// </summary>
            public IPAddress LocalAddress { get; private set; }

            /// <summary>
            /// The port number of the UDP endpoint on the local computer.
            /// </summary>
            public uint LocalPort { get; private set; }

            /// <summary>
            /// <see cref="UdpProcessRecord"/> の新しいインスタンスを初期化します。
            /// </summary>
            /// <param name="localAddress">The address of the UDP endpoint on the local computer.</param>
            /// <param name="localPort">The port number of the UDP endpoint on the local computer.</param>
            /// <param name="pId">The PID of the process that issued the call to the bind function for the UDP endpoint.</param>
            /// <param name="pidToProcessName">PID と プロセス名の関係をキャッシュするディクショナリを指定します。<c>null</c> の場合はキャッシュを行いません。省略可能です。既定値は <c>null</c> です。</param>
            public UdpProcessRecord(IPAddress localAddress, uint localPort, uint pId, Dictionary<uint, string> pidToProcessName = null)
            {
                LocalAddress = localAddress;
                LocalPort = localPort;
                SetProcessId(pId, pidToProcessName);
            }
        }

        /// <summary>
        /// サービス名とプロトコルから、ポート番号を得るディクショナリを保持します。
        /// </summary>
        private static Dictionary<Protocol, Dictionary<short, string>> portToServiceName = new Dictionary<Protocol, Dictionary<short, string>>();

        /// <summary>
        /// サービス名とプロトコルから、ポート番号を得るディクショナリを保持します。
        /// </summary>
        private static Dictionary<Protocol, Dictionary<string, short>> serviceNameToPort = new Dictionary<Protocol, Dictionary<string, short>>();

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
        /// IPv4 の TCP 接続を列挙したリストを返します。
        /// </summary>
        /// <param name="pidToProcessName">PID と プロセス名の関係をキャッシュするディクショナリを指定します。<c>null</c> の場合はキャッシュを行いません。省略可能です。既定値は <c>null</c> です。</param>
        /// <param name="throwException">例外を発生させるかどうか。省略可能です。既定値は <c>false</c> です。</param>
        /// <returns>IPv4 の TCP 接続のリスト。<see para="throwException"/> が <c>false</c> の場合に失敗した場合は、<c>null</c> を返します。</returns>
        /// <exception cref="Win32Exception"><see para="throwException"/> が <c>true</c> の場合に API の呼び出しに失敗しました。</exception>
        public static List<TcpProcessRecord> GetAllTcpv4Connections(Dictionary<uint, string> pidToProcessName = null, bool throwException = false)
        {
            int bufferSize = 0;
            List<TcpProcessRecord> tcpTableRecords = new List<TcpProcessRecord>();

            // Getting the size of TCP table, that is returned in 'bufferSize' variable.
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AddressFamily.AF_INET, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
            // ここでの result は必ず ERROR_INSUFFICIENT_BUFFER(0x0000007a) なので見ない

            // Allocating memory from the unmanaged memory of the process by using the
            // specified number of bytes in 'bufferSize' variable.
            IntPtr tcpTableRecordsPtr = Marshal.AllocCoTaskMem(bufferSize);

            try
            {
                // The size of the table returned in 'bufferSize' variable in previous
                // call must be used in this subsequent call to 'GetExtendedTcpTable'
                // function in order to successfully retrieve the table.
                result = GetExtendedTcpTable(tcpTableRecordsPtr, ref bufferSize, true, AddressFamily.AF_INET, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

                // Non-zero value represent the function 'GetExtendedTcpTable' failed,
                // hence empty list is returned to the caller function.
                if (result != 0)
                {
                    if (throwException == true)
                    {
                        throw new Win32Exception("GetExtendedTcpTable");
                    }
                    else
                    {
                        return null;
                    }
                }

                // Marshals data from an unmanaged block of memory to a newly allocated
                // managed object 'tcpRecordsTable' of type 'MIB_TCPTABLE_OWNER_PID'
                // to get number of entries of the specified TCP table structure.
                MIB_TCPTABLE_OWNER_PID tcpRecordsTable = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(tcpTableRecordsPtr, typeof(MIB_TCPTABLE_OWNER_PID));
                IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr + Marshal.SizeOf(tcpRecordsTable.dwNumEntries));

                // Reading and parsing the TCP records one by one from the table and
                // storing them in a list of 'TcpProcessRecord' structure type objects.
                for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(tableRowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    tcpTableRecords.Add(
                        new TcpProcessRecord(
                            new IPAddress(tcpRow.localAddr),
                            new IPAddress(tcpRow.remoteAddr),
                            BitConverter.ToUInt16(new byte[2] { tcpRow.localPort[1], tcpRow.localPort[0] }, 0),
                            BitConverter.ToUInt16(new byte[2] { tcpRow.remotePort[1], tcpRow.remotePort[0] }, 0),
                            tcpRow.owningPid,
                            tcpRow.state,
                            pidToProcessName));

                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(tcpTableRecordsPtr);
            }

            return tcpTableRecords;
        }

        /// <summary>
        /// IPv6 の TCP 接続を列挙したリストを返します。
        /// </summary>
        /// <param name="pidToProcessName">PID と プロセス名の関係をキャッシュするディクショナリを指定します。<c>null</c> の場合はキャッシュを行いません。省略可能です。既定値は <c>null</c> です。</param>
        /// <param name="throwException">例外を発生させるかどうか。省略可能です。既定値は <c>false</c> です。</param>
        /// <returns>IPv6 の TCP 接続のリスト。<see para="throwException"/> が <c>false</c> の場合に失敗した場合は、<c>null</c> を返します。</returns>
        /// <exception cref="Win32Exception"><see para="throwException"/> が <c>true</c> の場合に API の呼び出しに失敗しました。</exception>
        public static List<TcpProcessRecord> GetAllTcpv6Connections(Dictionary<uint, string> pidToProcessName = null, bool throwException = false)
        {
            int bufferSize = 0;
            List<TcpProcessRecord> tcpTableRecords = new List<TcpProcessRecord>();

            // Getting the size of TCP table, that is returned in 'bufferSize' variable.
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AddressFamily.AF_INET6, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
            // ここでの result は必ず ERROR_INSUFFICIENT_BUFFER(0x0000007a) なので見ない

            // Allocating memory from the unmanaged memory of the process by using the
            // specified number of bytes in 'bufferSize' variable.
            IntPtr tcpTableRecordsPtr = Marshal.AllocCoTaskMem(bufferSize);

            try
            {
                // The size of the table returned in 'bufferSize' variable in previous
                // call must be used in this subsequent call to 'GetExtendedTcpTable'
                // function in order to successfully retrieve the table.
                result = GetExtendedTcpTable(tcpTableRecordsPtr, ref bufferSize, true, AddressFamily.AF_INET6, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

                // Non-zero value represent the function 'GetExtendedTcpTable' failed,
                // hence empty list is returned to the caller function.
                if (result != 0)
                {
                    if (throwException == true)
                    {
                        throw new Win32Exception("GetExtendedTcpTable");
                    }
                    else
                    {
                        return null;
                    }
                }

                // Marshals data from an unmanaged block of memory to a newly allocated
                // managed object 'tcpRecordsTable' of type 'MIB_TCPTABLE_OWNER_PID'
                // to get number of entries of the specified TCP table structure.
                MIB_TCP6TABLE_OWNER_PID tcpRecordsTable = (MIB_TCP6TABLE_OWNER_PID)Marshal.PtrToStructure(tcpTableRecordsPtr, typeof(MIB_TCP6TABLE_OWNER_PID));
                IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr + Marshal.SizeOf(tcpRecordsTable.dwNumEntries));

                // Reading and parsing the TCP records one by one from the table and
                // storing them in a list of 'TcpProcessRecord' structure type objects.
                for (int row = 0; row < tcpRecordsTable.dwNumEntries; row++)
                {
                    MIB_TCP6ROW_OWNER_PID tcpRow = (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(tableRowPtr, typeof(MIB_TCP6ROW_OWNER_PID));
                    tcpTableRecords.Add(
                        new TcpProcessRecord(
                            new IPAddress(tcpRow.localAddr, tcpRow.localScopeId),
                            new IPAddress(tcpRow.remoteAddr, tcpRow.localScopeId),
                            BitConverter.ToUInt16(new byte[2] { tcpRow.localPort[1], tcpRow.localPort[0] }, 0),
                            BitConverter.ToUInt16(new byte[2] { tcpRow.remotePort[1], tcpRow.remotePort[0] }, 0),
                            tcpRow.owningPid,
                            tcpRow.state,
                            pidToProcessName));

                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(tcpTableRecordsPtr);
            }

            return tcpTableRecords;
        }

        /// <summary>
        /// IPv4 の UDP エンドポイントを列挙したリストを返します。
        /// </summary>
        /// <param name="pidToProcessName">PID と プロセス名の関係をキャッシュするディクショナリを指定します。<c>null</c> の場合はキャッシュを行いません。省略可能です。既定値は <c>null</c> です。</param>
        /// <param name="throwException">例外を発生させるかどうか。省略可能です。既定値は <c>false</c> です。</param>
        /// <returns>IPv4 の UDP エンドポイントのリスト。<see para="throwException"/> が <c>false</c> の場合に失敗した場合は、<c>null</c> を返します。</returns>
        /// <exception cref="Win32Exception"><see para="throwException"/> が <c>true</c> の場合に API の呼び出しに失敗しました。</exception>
        public static List<UdpProcessRecord> GetAllUdpv4Connections(Dictionary<uint, string> pidToProcessName = null, bool throwException = false)
        {
            int bufferSize = 0;
            List<UdpProcessRecord> udpTableRecords = new List<UdpProcessRecord>();

            // Getting the size of UDP table, that is returned in 'bufferSize' variable.
            uint result = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AddressFamily.AF_INET, UdpTableClass.UDP_TABLE_OWNER_PID);
            // ここでの result は必ず ERROR_INSUFFICIENT_BUFFER(0x0000007a) なので見ない

            // Allocating memory from the unmanaged memory of the process by using the
            // specified number of bytes in 'bufferSize' variable.
            IntPtr udpTableRecordPtr = Marshal.AllocCoTaskMem(bufferSize);

            try
            {
                // The size of the table returned in 'bufferSize' variable in previous
                // call must be used in this subsequent call to 'GetExtendedUdpTable'
                // function in order to successfully retrieve the table.
                result = GetExtendedUdpTable(udpTableRecordPtr, ref bufferSize, true, AddressFamily.AF_INET, UdpTableClass.UDP_TABLE_OWNER_PID);

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
                MIB_UDPTABLE_OWNER_PID udpRecordsTable = (MIB_UDPTABLE_OWNER_PID)Marshal.PtrToStructure(udpTableRecordPtr, typeof(MIB_UDPTABLE_OWNER_PID));
                IntPtr tableRowPtr = (IntPtr)((long)udpTableRecordPtr + Marshal.SizeOf(udpRecordsTable.dwNumEntries));

                // Reading and parsing the UDP records one by one from the table and
                // storing them in a list of 'UdpProcessRecord' structure type objects.
                for (int i = 0; i < udpRecordsTable.dwNumEntries; i++)
                {
                    MIB_UDPROW_OWNER_PID udpRow = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(tableRowPtr, typeof(MIB_UDPROW_OWNER_PID));
                    udpTableRecords.Add(
                        new UdpProcessRecord(
                            new IPAddress(udpRow.localAddr),
                            BitConverter.ToUInt16(new byte[2] { udpRow.localPort[1], udpRow.localPort[0] }, 0),
                            udpRow.owningPid,
                            pidToProcessName));

                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(udpRow));
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(udpTableRecordPtr);
            }

            return udpTableRecords;
        }

        /// <summary>
        /// IPv6 の UDP エンドポイントを列挙したリストを返します。
        /// </summary>
        /// <param name="pidToProcessName">PID と プロセス名の関係をキャッシュするディクショナリを指定します。<c>null</c> の場合はキャッシュを行いません。省略可能です。既定値は <c>null</c> です。</param>
        /// <param name="throwException">例外を発生させるかどうか。省略可能です。既定値は <c>false</c> です。</param>
        /// <returns>IPv6 の UDP エンドポイントのリスト。<see para="throwException"/> が <c>false</c> の場合に失敗した場合は、<c>null</c> を返します。</returns>
        /// <exception cref="Win32Exception"><see para="throwException"/> が <c>true</c> の場合に API の呼び出しに失敗しました。</exception>
        public static List<UdpProcessRecord> GetAllUdpv6Connections(Dictionary<uint, string> pidToProcessName = null, bool throwException = false)
        {
            int bufferSize = 0;
            List<UdpProcessRecord> udpTableRecords = new List<UdpProcessRecord>();

            // Getting the size of UDP table, that is returned in 'bufferSize' variable.
            uint result = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, AddressFamily.AF_INET6, UdpTableClass.UDP_TABLE_OWNER_PID);
            // ここでの result は必ず ERROR_INSUFFICIENT_BUFFER(0x0000007a) なので見ない

            // Allocating memory from the unmanaged memory of the process by using the
            // specified number of bytes in 'bufferSize' variable.
            IntPtr udpTableRecordPtr = Marshal.AllocCoTaskMem(bufferSize);

            try
            {
                // The size of the table returned in 'bufferSize' variable in previous
                // call must be used in this subsequent call to 'GetExtendedUdpTable'
                // function in order to successfully retrieve the table.
                result = GetExtendedUdpTable(udpTableRecordPtr, ref bufferSize, true, AddressFamily.AF_INET6, UdpTableClass.UDP_TABLE_OWNER_PID);

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
                            new IPAddress(udpRow.localAddr, udpRow.localScopeId),
                            BitConverter.ToUInt16(new byte[] { udpRow.localPort[1], udpRow.localPort[0] }, 0),
                            udpRow.owningPid,
                            pidToProcessName));

                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(udpRow));
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(udpTableRecordPtr);
            }

            return udpTableRecords;
        }

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
            if ((portToServiceName.ContainsKey(protocol) == true) &&
               (portToServiceName[protocol].ContainsKey(port) == true))
            {
                return portToServiceName[protocol][port];
            }

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

                if (portToServiceName.ContainsKey(protocol) == false)
                {
                    portToServiceName.Add(protocol, new Dictionary<short, string>());
                }
                portToServiceName[protocol].Add(port, srvent.s_name);

                return portToServiceName[protocol][port];
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
            if ((serviceNameToPort.ContainsKey(protocol) == true) &&
                (serviceNameToPort[protocol].ContainsKey(service) == true))
            {
                return serviceNameToPort[protocol][service];
            }

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

                if (serviceNameToPort.ContainsKey(protocol) == false)
                {
                    serviceNameToPort.Add(protocol, new Dictionary<string, short>());
                }
                serviceNameToPort[protocol].Add(service, Convert.ToInt16(IPAddress.NetworkToHostOrder(srvent.s_port)));

                return serviceNameToPort[protocol][service];
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
            // キャッシュは取得の都度生成すること。PID の再利用が発生すると、エントリが不正に取得されるため。
            Dictionary<uint, string> pidToProcessNameCache = new Dictionary<uint, string>();

            List<TcpProcessRecord> tcpv4Connections = GetAllTcpv4Connections(pidToProcessNameCache);
            List<TcpProcessRecord> tcpv6Connections = GetAllTcpv6Connections(pidToProcessNameCache);
            List<UdpProcessRecord> udpv4Connections = GetAllUdpv4Connections(pidToProcessNameCache);
            List<UdpProcessRecord> udpv6Connections = GetAllUdpv6Connections(pidToProcessNameCache);

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

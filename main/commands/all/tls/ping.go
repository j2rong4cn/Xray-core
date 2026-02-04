package tls

import (
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/apernet/quic-go"
	utls "github.com/refraction-networking/utls"

	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/main/commands/base"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

// cmdPing is the tls ping command
var cmdPing = &base.Command{
	UsageLine: "{{.Exec}} tls ping [-ip <ip>] [-h3] <domain>",
	Short:     "Ping the domain with TLS handshake",
	Long: `
Ping the domain with TLS handshake.

Arguments:

	-ip
		The IP address of the domain.
	-h3
		Use HTTP/3 (QUIC) for the TLS handshake.
`,
}

func init() {
	cmdPing.Run = executePing // break init loop
}

var pingIPStr = cmdPing.Flag.String("ip", "", "")
var h3 = cmdPing.Flag.Bool("h3", false, "")

func executePing(cmd *base.Command, args []string) {
	if cmdPing.Flag.NArg() < 1 {
		base.Fatalf("domain not specified")
	}

	domainWithPort := cmdPing.Flag.Arg(0)
	fmt.Println("TLS ping: ", domainWithPort)
	TargetPort := 443
	domain, port, err := net.SplitHostPort(domainWithPort)
	if err != nil {
		domain = domainWithPort
	} else {
		TargetPort, _ = strconv.Atoi(port)
	}
	tabWriter := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	var ip net.IP
	if len(*pingIPStr) > 0 {
		v := net.ParseIP(*pingIPStr)
		if v == nil {
			base.Fatalf("invalid IP: %s", *pingIPStr)
		}
		ip = v
	} else {
		v, err := net.ResolveIPAddr("ip", domain)
		if err != nil {
			base.Fatalf("Failed to resolve IP: %s", err)
		}
		ip = v.IP
	}
	fmt.Println("Using IP: ", ip.String()+":"+strconv.Itoa(TargetPort))

	fmt.Println("-------------------")
	fmt.Println("Pinging without SNI")
	if *h3 {
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			base.Fatalf("Failed to listen udp: %s", err)
		}
		remoteAddr := &net.UDPAddr{IP: ip, Port: TargetPort}
		quicConn, err := quic.DialEarly(context.Background(), udpConn, remoteAddr, &gotls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
			MaxVersion:         gotls.VersionTLS13,
			MinVersion:         gotls.VersionTLS13,
		}, nil)
		if err != nil {
			fmt.Println("Handshake failure: ", err)
		} else {
			fmt.Println("Handshake succeeded")
			state := quicConn.ConnectionState()
			printTLSStateDetail(tabWriter, state.TLS.Version, state.TLS.CurveID)
			printCertificates(tabWriter, state.TLS.PeerCertificates)
			tabWriter.Flush()
			quicConn.CloseWithError(0, "")
		}
		udpConn.Close()
	} else {
		tcpConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: ip, Port: TargetPort})
		if err != nil {
			base.Fatalf("Failed to dial tcp: %s", err)
		}
		tlsConn := GeneraticUClient(tcpConn, &gotls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
			MaxVersion:         gotls.VersionTLS13,
			MinVersion:         gotls.VersionTLS12,
		})
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("Handshake failure: ", err)
		} else {
			fmt.Println("Handshake succeeded")
			state := tlsConn.ConnectionState()
			curveID := *utils.AccessField[utls.CurveID](tlsConn.Conn, "curveID")
			printTLSStateDetail(tabWriter, state.Version, gotls.CurveID(curveID))
			printCertificates(tabWriter, state.PeerCertificates)
			tabWriter.Flush()
		}
		tlsConn.Close()
	}

	fmt.Println("-------------------")
	fmt.Println("Pinging with SNI")
	if *h3 {
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			base.Fatalf("Failed to listen udp: %s", err)
		}
		remoteAddr := &net.UDPAddr{IP: ip, Port: TargetPort}
		quicConn, err := quic.DialEarly(context.Background(), udpConn, remoteAddr, &gotls.Config{
			ServerName: domain,
			NextProtos: []string{"h3"},
			MaxVersion: gotls.VersionTLS13,
			MinVersion: gotls.VersionTLS13,
		}, nil)
		if err != nil {
			fmt.Println("Handshake failure: ", err)
		} else {
			fmt.Println("Handshake succeeded")
			state := quicConn.ConnectionState()
			printTLSStateDetail(tabWriter, state.TLS.Version, state.TLS.CurveID)
			printCertificates(tabWriter, state.TLS.PeerCertificates)
			tabWriter.Flush()
			quicConn.CloseWithError(0, "")
		}
		udpConn.Close()
	} else {
		tcpConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: ip, Port: TargetPort})
		if err != nil {
			base.Fatalf("Failed to dial tcp: %s", err)
		}
		tlsConn := GeneraticUClient(tcpConn, &gotls.Config{
			ServerName: domain,
			NextProtos: []string{"h2", "http/1.1"},
			MaxVersion: gotls.VersionTLS13,
			MinVersion: gotls.VersionTLS12,
		})
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("Handshake failure: ", err)
		} else {
			fmt.Println("Handshake succeeded")
			state := tlsConn.ConnectionState()
			curveID := *utils.AccessField[utls.CurveID](tlsConn.Conn, "curveID")
			printTLSStateDetail(tabWriter, state.Version, gotls.CurveID(curveID))
			printCertificates(tabWriter, state.PeerCertificates)
			tabWriter.Flush()
		}
		tlsConn.Close()
	}

	fmt.Println("-------------------")
	fmt.Println("TLS ping finished")
}

func printCertificates(tabWriter *tabwriter.Writer, certs []*x509.Certificate) {
	leaf := certs[0]
	var CAs []*x509.Certificate
	var length int
	for _, cert := range certs {
		length += len(cert.Raw)
		if len(cert.DNSNames) != 0 {
			leaf = cert
		} else {
			CAs = append(CAs, cert)
		}
	}
	fmt.Fprintf(tabWriter, "Certificate chain's total length:\t%d (certs count: %s)\n", length, strconv.Itoa(len(certs)))
	if leaf != nil {
		fmt.Fprintf(tabWriter, "Cert's signature algorithm:\t%s\n", leaf.SignatureAlgorithm.String())
		fmt.Fprintf(tabWriter, "Cert's publicKey algorithm:\t%s\n", leaf.PublicKeyAlgorithm.String())
		fmt.Fprintf(tabWriter, "Cert's leaf SHA256:\t%s\n", hex.EncodeToString(GenerateCertHash(leaf)))
		for _, ca := range CAs {
			fmt.Fprintf(tabWriter, "Cert's CA <%s> SHA256:\t%s\n", ca.Subject.CommonName, hex.EncodeToString(GenerateCertHash(ca)))
		}
		fmt.Fprintf(tabWriter, "Cert's allowed domains:\t%v\n", leaf.DNSNames)
	}
}

func printTLSStateDetail(tabWriter *tabwriter.Writer, version uint16, curveID gotls.CurveID) {
	var tlsVersion string
	switch version {
	case gotls.VersionTLS13:
		tlsVersion = "TLS 1.3"
	case gotls.VersionTLS12:
		tlsVersion = "TLS 1.2"
	}
	fmt.Fprintf(tabWriter, "TLS Version:\t%s\n", tlsVersion)
	if curveID != 0 {
		PostQuantum := (curveID == gotls.X25519MLKEM768)
		fmt.Fprintf(tabWriter, "TLS Post-Quantum key exchange:\t%t (%s)\n", PostQuantum, curveID.String())
	} else {
		fmt.Fprintf(tabWriter, "TLS Post-Quantum key exchange:  false (RSA Exchange)\n")
	}
}

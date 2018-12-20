package com.techiepark.util.ssl;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author techiepark
 *
 */
public class BCTlsSocketFactory {

	private static BCTlsSocketFactory socketFactory = new BCTlsSocketFactory();
	private static final Logger logger = LoggerFactory.getLogger(BCTlsSocketFactory.class);

	public static synchronized BCTlsSocketFactory getInstance() {
		if (socketFactory == null) {
			socketFactory = new BCTlsSocketFactory();
		}
		return socketFactory;
	}

	/**
	 * This method creates plain server socket and wraps the plain server socket
	 * with Bouncy Castle TlsServerProtocol and returns the secure
	 * tlsServerProtocol.
	 * 
	 * @param requestType
	 * @return
	 * @throws IOException
	 */

	public TlsServerProtocol getBCTlsServerSocket(Socket socket) throws IOException {
		TLSServerSocketConnectionFactory tlsServerFactory = TLSServerSocketConnectionFactory.getInstance();
		TlsServerProtocol tlsServerProtocol = tlsServerFactory.getTlsServerProtocol(socket);
		tlsServerProtocol.accept(tlsServerFactory.getDefaultTLSServer());
		return tlsServerProtocol;
	}

	public static void main(String args[]) {
		try {
			ServerSocket ssocket = new ServerSocket(7222);
			Socket socket = ssocket.accept();
			TlsServerProtocol tlsServerProtocol = BCTlsSocketFactory.getInstance().getBCTlsServerSocket(socket);
			logger.info("SSL/TLS socket accepted");
			logger.info("Do the desired operations with the accepted socket");
		} catch (Exception e) {
			logger.error("Exception ", e);
		}
	}
}

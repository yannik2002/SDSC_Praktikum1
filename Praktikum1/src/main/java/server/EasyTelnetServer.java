package server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;

import util.OnCommandLineListener;
import util.TelnetTerminal;

/**
 * EasyTelnetServer
 *
 * @author hexprobe <hexprobe@nbug.net>
 *
 * @license
 * This code is hereby placed in the public domain.
 *
 */
public class EasyTelnetServer {
    private String prompt = null;
    private ServerWorker serverWorker = null;
    private OnCommandLineListener onCommandLineListener = null;

    public void start(int port) throws IOException {
        if (serverWorker == null) {
            ServerSocket serverSocket = new ServerSocket(port);
            serverWorker = new ServerWorker(serverSocket);
            serverWorker.start();
        } else {
            throw new IllegalStateException();
        }
    }

    public void stop() throws InterruptedException {
        if (serverWorker != null) {
            serverWorker.terminate();
            serverWorker.join();
            serverWorker = null;
        } else {
            throw new IllegalStateException();
        }
    }

    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    public void setOnCommandLineListener(OnCommandLineListener onCommandLineListener) {
        this.onCommandLineListener = onCommandLineListener;
    }

    private class ServerWorker extends Thread {
        private final ServerSocket serverSocket;
        private volatile boolean terminated = false;

        public ServerWorker(ServerSocket serverSocket) {
            this.serverSocket = serverSocket;
        }

        public void terminate() {
            terminated = true;

            if (!serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    // Do nothing
                }
            }
        }

        @Override
        public void run() {
            try {
                while (!terminated) {
                    Socket socket = serverSocket.accept();
                    ClientWorker clientWorker = new ClientWorker(socket);
                    clientWorker.start();
                    System.out.println("Client connected!");
                }
            } catch (IOException e) {
                // Do nothing
            } finally {
                if (!serverSocket.isClosed()) {
                    try {
                        serverSocket.close();
                    } catch (IOException e) {
                        // Do nothing
                    }
                }
            }
            System.out.println("Server shutdown initiated!");
        }
    }

    private class ClientWorker extends Thread {
        private final Socket socket;

        public ClientWorker(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                TelnetTerminal telnet =
                    new TelnetTerminal(
                        new DataOutputStream(socket.getOutputStream()),
                        new DataInputStream(socket.getInputStream()),
                        Charset.forName("UTF-8"));
                if (prompt != null) {
                    telnet.setPrompt(prompt);
                }
                telnet.setOnCommandLineListener(onCommandLineListener);
                telnet.run();
            } catch (IOException e) {
                // Do nothing
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (!socket.isClosed()) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        // Do nothing
                    }
                }
            }
            System.out.println("Client disconnected!");
        }
    }
}

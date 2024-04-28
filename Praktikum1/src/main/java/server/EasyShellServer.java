package server;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.bouncycastle.cms.CMSException;

import util.EasyTerminal;
import util.OnCommandLineListener;
import util.StringUtils;

/**
 * EasyShellServer
 *
 * @author hexprobe <hexprobe@nbug.net>
 *
 * @license
 *          This code is hereby placed in the public domain.
 *
 */
public class EasyShellServer {
    private EasyTelnetServer telnetd = null;

    private final Map<String, Command> commands = new HashMap<String, Command>();
    {
        registerCommand("exit", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal) throws IOException {
                terminal.close();
            }
        });

        registerCommand("help", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal) throws IOException {
                terminal.writeLine(StringUtils.join(" ", commands.keySet()));
                terminal.flush();
            }
        });

        registerCommand("?", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal) throws IOException {
                terminal.writeLine(StringUtils.join(" ", commands.keySet()));
                terminal.flush();
            }
        });

        registerCommand("logmode", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal) throws IOException {
                if (terminal.isLogMode()) {
                    terminal.setLogMode(false);
                    terminal.writeLine("LogMode disabled.");
                } else {
                    terminal.setLogMode(true);
                    terminal.writeLine("LogMode enabled.");
                }
                terminal.flush();
            }
        });

        registerCommand("shutdown", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal) throws IOException {
                terminal.close();
                try {
                    telnetd.stop();
                } catch (Exception e) {
                    System.out.println(e);
                }
            }
        });
    }

    public void start(int port) throws IOException {
        if (telnetd == null) {
            EasyTelnetServer srv = new EasyTelnetServer();
            srv.setOnCommandLineListener(new CommandProcessor());
            srv.start(port);
            telnetd = srv;
        } else {
            throw new IllegalStateException();
        }
    }

    public void stop() throws InterruptedException {
        if (telnetd != null) {
            telnetd.stop();
            telnetd = null;
        } else {
            throw new IllegalStateException();
        }
    }

    public void registerCommand(String name, Command command) {
        commands.put(name.toLowerCase(Locale.getDefault()), command);
    }

    private class CommandProcessor implements OnCommandLineListener {
        @Override
        public void OnCommandLine(EasyTerminal terminal, String commandLine) throws IOException {
            try {
                commandLine = commandLine.trim();
                String[] tokens = commandLine.split(" ");
                String name = tokens[0].toLowerCase(Locale.getDefault());
                Command command = commands.get(name);
                if (command != null) {
                    System.out.println("Client sent command: " + commandLine);
                    command.execute(name, commandLine.substring(name.length()).trim(), terminal);
                } else if (name.isEmpty()) {
                    System.out.println("Client sent empty command.");
                } else {
                    System.out.println("Client sent unknown command!");
                    terminal.writeLine("Command not found.");
                    terminal.flush();
                }
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                e.printStackTrace();
                terminal.writeLine("Error: " + e.toString());
                terminal.flush();
            }
        }
    }

    public interface Command {
        void execute(String name, String argument, EasyTerminal terminal) throws IOException, CMSException, CertificateEncodingException, NoSuchAlgorithmException, NoSuchProviderException, Exception;
    }
}

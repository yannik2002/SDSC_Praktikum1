package util;

import java.io.*;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * VT100Terminal
 *
 * @author hexprobe <hexprobe@nbug.net>
 *
 * @license
 * This code is hereby placed in the public domain.
 *
 */
public class TelnetTerminal implements EasyTerminal {
    public static final int BS = 0x08;
    public static final int CR = 0x0d;
    public static final int ESC = 0x1b;
    public static final int DEL = 0x7f;

    public static final int UTF8_FIRST_BEGIN = 0x20;
    public static final int UTF8_FIRST_MAX_1 = 0x7f;
    public static final int UTF8_FIRST_MAX_2 = 0xdf;
    public static final int UTF8_FIRST_MAX_3 = 0xef;
    public static final int UTF8_FIRST_MAX_4 = 0xf7;
    public static final int UTF8_FIRST_MAX_5 = 0xfb;
    public static final int UTF8_FIRST_MAX_6 = 0xfd;
    public static final int UTF8_FIRST_END = UTF8_FIRST_MAX_6;

    public static final int IAC = 0xff;
    public static final int IAC_WILL = 0xfb;
    public static final int IAC_DO = 0xfd;
    public static final int IAC_ECHO = 0x01;
    public static final int IAC_BINARY = 0x00;
    public static final int IAC_SGA = 0x03;
    public static final int IAC_NAWS = 0x1f;
    public static final int IAC_SB = 0xfa;
    public static final int IAC_SE = 0xf0;

    public static final int CSI = 0x5b;
    public static final int CSI_FINAL_BEGIN = 0x40;
    public static final int CSI_FINAL_END = 0x7e;

    private static final int TAB_SIZE = 8;

    private static final byte NONE = 0;
    private static final byte FIRST = 1;
    private static final byte SUBSEQ = 2;

    private final Charset encoding;
    private final DataOutputStream dataOutputStream;
    private final DataInputStream dataInputStream;
    private final Map<String, Object> session;

    private String prompt = "> ";
    private OnCommandLineListener onCommandLineListener = null;

    private int x = 0;
    private int y = 0;
    private int width = 80;
    private int height = 24;
    private byte[] screen;
    private boolean echo = true;
    private boolean logMode = false;

    public TelnetTerminal(DataOutputStream dataOutputStream, DataInputStream dataInputStream, Charset encoding) {
        this.encoding = encoding;
        this.dataOutputStream = dataOutputStream;
        this.dataInputStream = dataInputStream;
        this.screen = new byte[height * width];
        this.session = new HashMap<String, Object>();
    }

    public void run() throws IOException {
        writeInitialSequence();

        while (true) {
            writePrompt();

            String line = readLine();
            if (onCommandLineListener != null) {
                onCommandLineListener.OnCommandLine(this, line);
            }
        }
    }

    public void setOnCommandLineListener(OnCommandLineListener onCommandLineListener) {
        this.onCommandLineListener = onCommandLineListener;
    }

    @Override
    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    @Override
    public void close() throws IOException {
        dataInputStream.close();
    }

    @Override
    public InputStream getInputStream() {
        return dataInputStream;
    }

    @Override
    public Charset getEncoding() {
        return encoding;
    }

    @Override
    public boolean isEcho() {
        return echo;
    }

    @Override
    public void setEcho(boolean enable) {
        echo = enable;
    }

    @Override
    public boolean isLogMode() {
        return logMode;
    }

    @Override
    public void setLogMode(boolean logMode) {
        this.logMode = logMode;
    }

    @Override
    public Set<String> getSessionKeys() {
        return session.keySet();
    }

    @Override
    public Object getSession(String key) {
        return session.get(key);
    }

    @Override
    public void setSession(String key, Object value) {
        session.put(key, value);
    }

    @Override
    public String readLine() throws IOException {
        StringBuilder lineBuf = new StringBuilder();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        while (true) {
            int readByte = read(dataInputStream);

            if (UTF8_FIRST_BEGIN <= readByte && readByte <= UTF8_FIRST_END && readByte != DEL) {
                buf.reset();
                buf.write(readByte);

                int n;

                if (readByte <= UTF8_FIRST_MAX_1) {
                    n = 0;
                } else if (readByte <= UTF8_FIRST_MAX_2) {
                    n = 1;
                } else if (readByte <= UTF8_FIRST_MAX_3) {
                    n = 2;
                } else if (readByte <= UTF8_FIRST_MAX_4) {
                    n = 3;
                } else if (readByte <= UTF8_FIRST_MAX_5) {
                    n = 4;
                } else if (readByte <= UTF8_FIRST_MAX_6) {
                    n = 5;
                } else {
                    n = 0;
                }

                for (; n > 0; n--) {
                    buf.write(read(dataInputStream));
                }

                String tmp = buf.toString(encoding.name());
                lineBuf.append(tmp);
                if (echo) {
                    write(tmp);
                    flush();
                }
            } else {
                switch (readByte) {
                case CR:
                    if (echo) {
                        writeLine("");
                        flush();
                    }
                    return lineBuf.toString();

                case DEL:
                case BS:
                    if (lineBuf.length() > 0) {
                        backSpace();
                        String tmp = biteTail(lineBuf.toString());
                        lineBuf.setLength(0);
                        lineBuf.append(tmp);
                    }
                    break;

                case ESC:
                readByte = read(dataInputStream);
                    if (readByte == CSI) {
                        do {
                            readByte = read(dataInputStream);
                        } while (!(CSI_FINAL_BEGIN <= readByte && readByte <= CSI_FINAL_END));
                    }
                    break;

                case IAC:
                readByte = read(dataInputStream);
                    switch (readByte) {
                    case IAC_SB:
                    readByte = read(dataInputStream);
                        if (readByte == IAC_NAWS) {
                            short width = dataInputStream.readShort();
                            short height = dataInputStream.readShort();
                            setScreenSize(width, height);
                        }
                        break;

                    case IAC_SE:
                        break;

                    default:
                        read(dataInputStream);
                    }
                    break;
                }
            }
        }
    }

    @Override
    public void write(String s) throws IOException {
        char hi = 0;
        char lo;
        int w;

        for (char c : s.toCharArray()) {
            if (Character.isHighSurrogate(c)) {
                hi = c;
                continue;
            } else if (Character.isLowSurrogate(c)) {
                lo = c;
            } else {
                hi = c;
                lo = 0;
            }

            switch (hi) {
            case '\r':
                x = 0;
                dataOutputStream.write(String.valueOf(hi).getBytes(encoding.name()));
                break;

            case '\n':
            dataOutputStream.write(String.valueOf(hi).getBytes(encoding.name()));
                newLine(false);
                break;

            case '\t':
                int newX = x + TAB_SIZE;
                newX -= newX % TAB_SIZE;

                for (int i = 0; x < newX && x < width; x++, i++) {
                    screen[y * width + x] = i == 0 ? FIRST : SUBSEQ;
                }

                dataOutputStream.write(String.valueOf(hi).getBytes(encoding.name()));

                if (x == width) {
                    if (logMode) {
                        x = 0;
                        newLine(true);
                    } else {
                        dataOutputStream.write(" \r".getBytes(encoding.name()));

                        x = 0;
                        newLine(false);
                    }
                }
                break;

            default:
                if (hi < ' ' || hi == DEL) {
                    break;
                }

                w = StringUtils.getPhysicalWidth(hi);

                if (x + w > width) {
                    if (logMode) {
                        x = 0;
                        newLine(true);
                    } else {
                        for (; x < width; x++) {
                            screen[y * width + x] = NONE;
                            dataOutputStream.write(" ".getBytes(encoding.name()));
                        }
                        dataOutputStream.write(" \r".getBytes(encoding.name()));

                        x = 0;
                        newLine(false);
                    }
                }

                for (int i = 0; i < w; i++, x++) {
                    screen[y * width + x] = i == 0 ? FIRST : SUBSEQ;
                }

                if (lo > 0) {
                    dataOutputStream.write(String.valueOf(new char[]{hi, lo}).getBytes(encoding.name()));
                } else {
                    dataOutputStream.write(String.valueOf(hi).getBytes(encoding.name()));
                }

                if (x == width) {
                    if (logMode) {
                        x = 0;
                        newLine(true);
                    } else {
                        dataOutputStream.write(" \r".getBytes(encoding.name()));

                        x = 0;
                        newLine(false);
                    }
                }
            }
        }
    }

    @Override
    public void writeLine(String s) throws IOException {
        write(s);
        write("\r\n");
    }

    @Override
    public void flush() throws IOException {
        dataOutputStream.flush();
    }

    private void writePrompt() throws IOException {
        write(prompt);
        flush();
    }

    public void writeInitialSequence() throws IOException {
        writeBytes(dataOutputStream, IAC, IAC_WILL, IAC_ECHO);
        writeBytes(dataOutputStream, IAC, IAC_DO, IAC_SGA);
        writeBytes(dataOutputStream, IAC, IAC_WILL, IAC_SGA);
        writeBytes(dataOutputStream, IAC, IAC_DO, IAC_BINARY);
        writeBytes(dataOutputStream, IAC, IAC_WILL, IAC_BINARY);
        writeBytes(dataOutputStream, IAC, IAC_DO, IAC_NAWS);
    }
    
    private void setScreenSize(int width, int height) throws IOException {
        if (this.width != width || this.height != height) {
            this.width = width;
            this.height = height;

            screen = new byte[height * width];

            clearScreen();
        }
    }

    private void backSpace() throws IOException {
        int i;
        boolean found = false;
        int orgX = x;
        int orgY = y;

        for (i = y * width + x; i >= 0; i--) {
            byte crr = screen[i];
            screen[i] = NONE;
            if (crr == FIRST) {
                found = true;
                break;
            }
        }

        if (found) {
            for (; i >= 0; i--) {
                if (screen[i] != NONE) {
                    break;
                }
            }
            i++;

            x = i % width;
            y = i / width;

            if (moveRelative(x - orgX, y - orgY)) {
                dataOutputStream.write(ESC);
                dataOutputStream.write("[J".getBytes(encoding.name()));
                dataOutputStream.flush();
            }
        }
    }
    
    private boolean moveRelative(int offX, int offY) throws IOException {
        if (offX > 0) {
            dataOutputStream.write(ESC);
            dataOutputStream.write(String.format("[%dC", offX).getBytes(encoding.name()));
        } else if(offX < 0) {
            dataOutputStream.write(ESC);
            dataOutputStream.write(String.format("[%dD", -offX).getBytes(encoding.name()));
        }
        
        if (offY > 0) {
            dataOutputStream.write(ESC);
            dataOutputStream.write(String.format("[%dB", offY).getBytes(encoding.name()));
        } else if(offY < 0) {
            dataOutputStream.write(ESC);
            dataOutputStream.write(String.format("[%dA", -offY).getBytes(encoding.name()));
        }
        
        return offX != 0 || offY != 0;
    }

    private void newLine(boolean move) throws IOException {
        y += 1;
        if (y >= height) {
            y = height - 1;

            for (int i = 0; i < height - 1; i++) {
                for (int j = 0; j < width; j++) {
                    screen[i * width + j] = screen[(i + 1) * width + j];
                }
            }

            Arrays.fill(screen, (height - 1) * width, screen.length, NONE);

            if (move) {
                dataOutputStream.write(ESC);
                dataOutputStream.write("[S".getBytes(encoding.name()));
            }
        }

        if (move) {
            dataOutputStream.write(ESC);
            dataOutputStream.write("[E".getBytes(encoding.name()));
        }
    }

    private void clearScreen() throws IOException {
        x = 0;
        y = 0;

        dataOutputStream.write(ESC);
        dataOutputStream.write("[1;1H".getBytes(encoding.name()));

        Arrays.fill(screen, NONE);

        dataOutputStream.write(ESC);
        dataOutputStream.write("[J".getBytes(encoding.name()));
        dataOutputStream.flush();

        writePrompt();
    }

    private static int read(InputStream s) throws IOException {
        int b = s.read();
        if (b >= 0) {
            return b;
        } else {
            throw new IOException();
        }
    }

    private static void writeBytes(OutputStream s, int... b) throws IOException {
        for (int i : b) {
            s.write(i);
        }
    }

    private static String biteTail(String s) {
        char[] str = s.toCharArray();
        for (int i = str.length - 1; i >= 0; i--) {
            if (!Character.isLowSurrogate(str[i])) {
                return new String(str, 0, i);
            }
        }
        return "";
    }
}

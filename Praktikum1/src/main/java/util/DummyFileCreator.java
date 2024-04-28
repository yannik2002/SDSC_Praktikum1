package util;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Random;

public class DummyFileCreator {
	static int filesize = 42 * 1024;

	static File dir = new File(System.getProperty("user.dir"));

	public static void createFile() {
		byte[] bytes = new byte[filesize];
		BufferedOutputStream bos = null;
		FileOutputStream fos = null;

		try {
			Random rand = new Random();

			String name = "hashme.txt";
			File file = new File(dir, name);

			fos = new FileOutputStream(file);
			bos = new BufferedOutputStream(fos);

			rand.nextBytes(bytes);
			bos.write(bytes);

			bos.flush();
			bos.close();
			fos.flush();
			fos.close();

		} catch (FileNotFoundException fnfe) {
			System.out.println("File not found" + fnfe);
		} catch (IOException ioe) {
			System.out.println("Error while writing to file" + ioe);
		} finally {
			try {
				if (bos != null) {
					bos.flush();
					bos.close();
				}
				if (fos != null) {
					fos.flush();
					fos.close();
				}
			} catch (Exception e) {
				System.out.println("Error while closing streams" + e);
			}
		}
	}

}
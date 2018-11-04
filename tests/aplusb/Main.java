import java.io.PrintWriter;
import java.util.Scanner;
public class Main {
	static PrintWriter cout = new PrintWriter(System.out, true);
	static Scanner cin = new Scanner(System.in);

	public static void main(String[] args) {
		while (cin.hasNext()) {
			long a = cin.nextLong();
			long b = cin.nextLong();
			cout.println(a + b);
		}
		cin.close();
		cout.close();
	}
}

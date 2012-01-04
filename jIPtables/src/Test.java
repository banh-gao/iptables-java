import net.sf.jIPtables.log.LogListener;
import net.sf.jIPtables.log.LogTracker;
import net.sf.jIPtables.log.Packet;



public class Test {
	public static void main(String[] args) {
		LogTracker t = LogTracker.getInstance();
		t.addLogListener(new LogListener() {
			
			@Override
			public void onNewLog(Packet newPacket) {
				if("INDROPPED".equals(newPacket.getPrefix()))
					System.out.println("IF: "+ newPacket.getINInterface());
			}
		});
	}
}

package org.operatorfoundation.shapeshifter.shadow.java;
//
//import java.io.IOException;
//import java.net.Socket;
//import java.util.Calendar;
//import java.util.Random;
//import java.util.concurrent.Executors;
//import java.util.concurrent.ScheduledExecutorService;
//
//public class Hole {
//    public void startHole(int timeoutDelay, Socket socket) throws IOException {
//        long currentTimeInSeconds = Calendar.getInstance().getTimeInMillis() / 1000;
//        long endTime = currentTimeInSeconds + timeoutDelay;
//        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
//        startPacketDelayTimer(endTime, socket, scheduler);
//    }
//
//    public void startPacketDelayTimer(long mainTimer, Socket socket, ScheduledExecutorService scheduler) throws IOException {
//        long currentTimeInSeconds = Calendar.getInstance().getTimeInMillis() / 1000;
//        int packetTimerMax = 5;
//        int packetTimerMin = 1;
//        int packetSizeMax = 1440 - 16; // max TCP size without encryption overhead
//        int packetSizeMin = 1;
//        int countDownStarter = betweenRNG(packetTimerMax, packetTimerMin);
//
//        if (mainTimer - currentTimeInSeconds > 0) {
//            Runnable runnable = new Runnable() {
//                @Override
//                public void run() {
//                    int packetSize = betweenRNG(packetSizeMax, packetSizeMin);
//                    byte[] packet = new byte[packetSize];
//                    Random random = new java.security.SecureRandom();
//                    random.nextBytes(packet);
//                    try {
//                        socket.getOutputStream().write(packet);
//                    } catch (IOException e) {
//                        e.printStackTrace();
//                    }
//                    try {
//                        startPacketDelayTimer(mainTimer, socket, scheduler);
//                    } catch (IOException e) {
//                        e.printStackTrace();
//                    }
//
//                }
//            };
//        } else {
//            scheduler.shutdown();
//            socket.close();
//        }
//    }
//
//    public int betweenRNG(int maxNumber, int minNumber) {
//        Random r = new java.security.SecureRandom();
//        return r.nextInt(maxNumber - minNumber) + minNumber;
//    }
//}

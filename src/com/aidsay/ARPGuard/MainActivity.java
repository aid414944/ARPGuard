package com.aidsay.ARPGuard;

import android.app.Activity;
import android.content.Context;
import android.net.DhcpInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.*;

public class MainActivity extends Activity {

    private WifiManager wifiManager;
    private TextView tvSSID;
    private TextView tvBSSID;
    private TextView tvGatewayMac;
    private Switch btnLockGatewayMac;

    private String bssid;
    private String gatewayIp;
    private String gatewayMac;

    private Handler handler;
    Runnable runnable = new Runnable() {
        @Override
        public void run() {
            updata();
            handler.postDelayed(this, 500);
        }
    };

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        wifiManager = (WifiManager)getSystemService(Context.WIFI_SERVICE);
        tvSSID =(TextView)findViewById(R.id.tvSSID);
        tvBSSID = (TextView)findViewById(R.id.tvBSSID);
        tvGatewayMac = (TextView)findViewById(R.id.tvGatewayMac);
        btnLockGatewayMac = (Switch)findViewById(R.id.btnLockGatewayMac);
        btnLockGatewayMac.setOnCheckedChangeListener(onCheckedChangeListener);

        handler = new Handler();
        handler.post(runnable);

    }

    private void updata(){
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
        tvSSID.setText("当前热点："+wifiInfo.getSSID());
        bssid = wifiInfo.getBSSID();
        tvBSSID.setText("热点MAC："+bssid);
        DhcpInfo dhcpInfo = wifiManager.getDhcpInfo();
        gatewayIp = ipIntToString(dhcpInfo.gateway);
        gatewayMac = getMacFromIp(gatewayIp);
        tvGatewayMac.setText("网关MAC："+gatewayMac);

        if (gatewayMac == null || gatewayIp == null) {
            btnLockGatewayMac.setEnabled(false);
            btnLockGatewayMac.setChecked(false);
            tvGatewayMac.setTextColor(0xFF000000);
            return;
        }
        btnLockGatewayMac.setEnabled(true);

        if (!gatewayMac.equals(bssid)){
            // 不相等表示很有正在遭受ARP攻击，以红色显示。
            tvGatewayMac.setTextColor(0xFFFF0000);
        }else {
            tvGatewayMac.setTextColor(0xFF000000);
        }

        btnLockGatewayMac.setOnCheckedChangeListener(null);
        if (isLockedTheGatewayMac()){
            btnLockGatewayMac.setChecked(true);
        }else {
            btnLockGatewayMac.setChecked(false);
        }
        btnLockGatewayMac.setOnCheckedChangeListener(onCheckedChangeListener);

    }

    private CompoundButton.OnCheckedChangeListener onCheckedChangeListener = new CompoundButton.OnCheckedChangeListener(){
        @Override
        public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {

            File arp = new File("/system/xbin/arp");
            if (!arp.exists()){
                if(!initComponents()){
                    Toast.makeText(MainActivity.this, "初始化防御组件失败！", Toast.LENGTH_SHORT).show();
                }
            }

            if (isChecked){
                if (!rootExec("arp -s " + gatewayIp + " " + bssid + "\n")){
                    Toast.makeText(MainActivity.this, "锁定失败！", Toast.LENGTH_SHORT).show();
                }
            }else {
                rootExec("arp -d " + gatewayIp + "\nexit\n");
            }
        }
    };

    private boolean initComponents(){
        try {
            InputStream inputStream = MainActivity.this.getAssets().open("armv7l/arp");
            FileOutputStream outputStream = MainActivity.this.openFileOutput("arp", MODE_PRIVATE);
            byte[] buffer = new byte[4096];
            int count = 0;
            while ((count=inputStream.read(buffer))!= -1){
                outputStream.write(buffer, 0, count);
            }
            outputStream.flush();
            inputStream.close();
            outputStream.close();
            boolean result = rootExec(
                     "mount -o remount,rw /dev/block/stl6 /system\n"
                    +"cp -f /data/data/"+MainActivity.this.getPackageName()+"/files/arp /system/xbin/arp\n"
                    +"chmod 755 /system/xbin/arp\n"
                    +"mount -o remount,ro /dev/block/stl6 /system\n");
            return result;
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
    }

    private boolean isLockedTheGatewayMac(){
        try {
            BufferedReader arpCache = new BufferedReader(new FileReader("/proc/net/arp"));
            String line;
            while ((line = arpCache.readLine()) != null){
                if (line.contains(gatewayIp) && line.contains(bssid) && line.contains("0x6")) return true;
            }
            arpCache.close();
        }catch (IOException e){
            e.printStackTrace();
            Log.e("isLockedTheGatewayMac(String ip)", "IOException");
            return false;
        }
        return false;
    }

    private boolean rootExec(String cmd){
        try {
            Process su = Runtime.getRuntime().exec("su");
            DataOutputStream dataOutputStream = new DataOutputStream(su.getOutputStream());
            dataOutputStream.writeBytes(cmd+"\nexit\n");
            dataOutputStream.flush();
            dataOutputStream.close();
            su.waitFor();
            // 一般来说退出值是0，表示执行成功
            if (su.exitValue() == 0){
                return true;
            }else {
                return false;
            }
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
    }

    private String ipIntToString(int ip){
        String result =
                String.valueOf((ip>>0) & 0xff)+"."+
                String.valueOf((ip>>8) & 0xff)+"."+
                String.valueOf((ip>>16) & 0xff)+"."+
                String.valueOf((ip>>24) & 0xff);
        return result;
    }

    // 从ARP缓存中获取IP对应的MAC
    private String getMacFromIp(String ip){
        try {
            BufferedReader arpCache = new BufferedReader(new FileReader("/proc/net/arp"));
            String line;
            String[] sArray;
            while ((line = arpCache.readLine()) != null){
                sArray =  line.split(" +");
                if (sArray[0].equals(ip)){
                    return sArray[3];
                }
            }
            arpCache.close();
        }catch (IOException e){
            e.printStackTrace();
            Log.e("getMacFromIp(String ip)", "IOException");
            return null;
        }
        return null;
    }

}

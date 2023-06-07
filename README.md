<p align="center">
<img src="https://github.com/zerobyte-id/Portablehack/assets/44427665/10c0e217-4980-4496-b502-6055e39d5549"  width="30%" align="center">
</p>

---------------

Portablehack is a open-source web-based penetration test tool designed to simplify the process of assessing the security and vulnerability. This tool is designed like a Swiss-Knife that has its own features but is interrelated.

![image](https://github.com/zerobyte-id/Portablehack/assets/44427665/ea586dde-48dc-4c6b-b299-1812546a181c)

**Note:** It should be used responsibly and ethically. Always obtain proper authorization before conducting any security assessments and adhere to legal and ethical guidelines.

## Installation

1. Clone the "Portablehack" repository by running the following command.
```
git clone https://github.com/zerobyte-id/Portablehack
```

2. Navigate to the Portablehack directory.
```
cd Portablehack
```

3. Create a copy of the `.env.example` file and name it `.env`.
```
cp .env.example .env
```

4. Open the `.env` file and make any necessary adjustments. You can skip this step if you want to use the default configuration.

Please note that some steps require administrative privileges (e.g., sudo) depending on your system configuration.

5. Run the following command to start the deployment using Docker Compose.
```
sudo docker-compose up -d
```

Congratulations! You have successfully completed the installation process for Portablehack. The application should now be up and running in `http://your-instance:5000`.

## Credits

**This application is built by several other applications:**
- [NMAP](https://nmap.org/)
- [Nuclei (@projectdiscovery)](https://github.com/projectdiscovery/nuclei)
- [iptoasn-webservice (@jedisct1)](https://github.com/jedisct1/iptoasn-webservice)
- [Naabu (@projectdiscovery)](https://github.com/projectdiscovery/naabu)
- [Smap (@s0md3v)](https://github.com/s0md3v/Smap)
- [Subfinder (@projectdiscovery)](https://github.com/projectdiscovery/subfinder)
- [Dnsx (@projectdiscovery)](https://github.com/projectdiscovery/dnsx)

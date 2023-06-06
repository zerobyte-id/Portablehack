# Portablehack

Portablehack is a open-source web-based penetration test tool designed to simplify the process of assessing the security.

## Installation

Clone with git.

```
git clone https://github.com/zerobyte-id/Portablehack
```

Move to `Portablehack` main directory.

```
cd Portablehack
```

Copy `.env` file.

```
cp .env.example .env
```

Adjust `.env` file.

Deploy with Docker Compose.

```
sudo docker-compose up -d
```

Dashboard access `http://your-instance:5000/`.

## Credits

**This application is built by several other applications:**
- [NMAP](https://nmap.org/)
- [Nuclei (@projectdiscovery)](https://github.com/projectdiscovery/nuclei)
- [iptoasn-webservice (@jedisct1)](https://github.com/jedisct1/iptoasn-webservice)
- [Naabu (@projectdiscovery)](https://github.com/projectdiscovery/naabu)
- [Smap (@s0md3v)](https://github.com/s0md3v/Smap)

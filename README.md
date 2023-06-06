# Portablehack

Portablehack is a web-based open-source penetration test tool designed to simplify the process of assessing the security.

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

**This application is supported by several applications, big thanks to**
- [NMAP](https://nmap.org/)
- [Nuclei (@projectdiscovery)](https://github.com/projectdiscovery/nuclei)

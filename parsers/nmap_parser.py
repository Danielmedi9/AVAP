from utils.logger import log_ok, log_error


def parse_nmap(path: str) -> dict:
    ports = []

    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if "open" in line and ("/tcp" in line or "/udp" in line):
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        port_entry = {
                            "port":    parts[0],
                            "state":   parts[1],
                            "service": parts[2],
                            "version": " ".join(parts[3:]) if len(parts) > 3 else ""
                        }
                        ports.append(port_entry)

        log_ok("PARSER", f"Nmap: {len(ports)} puertos abiertos encontrados")
        return {"ports": ports, "count": len(ports)}

    except FileNotFoundError:
        log_error("PARSER", f"Archivo Nmap no encontrado: {path}")
        return {"ports": [], "count": 0}

    except Exception as e:
        log_error("PARSER", f"Error parseando Nmap: {e}")
        return {"ports": [], "count": 0}

#!/usr/bin/env bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}        VULNERABILITY ANALYSIS PIPELINE${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo ""

if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}✗ Python no encontrado. Instala Python 3.11+ desde https://python.org${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python: $($PYTHON --version 2>&1)${NC}"

if ! command -v docker &>/dev/null; then
    echo -e "${RED}✗ Docker no encontrado. Instala Docker Desktop desde https://docker.com${NC}"
    exit 1
fi
if ! docker info &>/dev/null 2>&1; then
    echo -e "${RED}✗ Docker no está activo. Arranca Docker Desktop e inténtalo de nuevo.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker activo${NC}"

if [ ! -d "venv" ]; then
    echo -e "${YELLOW}→ Creando entorno virtual...${NC}"
    $PYTHON -m venv venv
    echo -e "${GREEN}✓ Entorno virtual creado${NC}"
fi

if [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
elif [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo -e "${RED}✗ No se encontró el script de activación del venv.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Entorno virtual activado${NC}"

echo -e "${YELLOW}→ Instalando dependencias...${NC}"
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "${GREEN}✓ Dependencias instaladas${NC}"

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo ""

if [ $# -gt 0 ]; then
    echo -e "${CYAN}→ Ejecutando con argumentos: $@${NC}"
    echo ""
    python main.py "$@"
else
    echo -e "${BOLD}  ¿Qué quieres escanear?${NC}"
    echo ""
    echo -e "  ${CYAN}1)${NC} OWASP Juice Shop ${YELLOW}(entorno de prueba Docker)${NC}"
    echo -e "     Levanta Juice Shop automáticamente y lo escanea."
    echo -e "     Incluye: Nmap + ZAP + Trivy"
    echo ""
    echo -e "  ${CYAN}2)${NC} Target externo ${YELLOW}(tu propia aplicación)${NC}"
    echo -e "     Escanea una URL que ya esté en ejecución."
    echo -e "     Incluye: Nmap + ZAP"
    echo ""
    echo -e "  ${CYAN}3)${NC} Salir"
    echo ""
    echo -ne "  ${BOLD}Elige una opción [1/2/3]:${NC} "
    read -r OPCION

    echo ""

    case "$OPCION" in
        1)
            echo -e "${YELLOW}→ Modo: OWASP Juice Shop${NC}"
            echo ""

            echo -ne "  ¿Abrir el dashboard en el navegador al finalizar? [S/n]: "
            read -r BROWSER
            BROWSER_FLAG=""
            if [[ "$BROWSER" =~ ^[Nn]$ ]]; then
                BROWSER_FLAG="--no-browser"
            fi

            echo ""
            python main.py --juice-shop $BROWSER_FLAG
            ;;

        2)
            echo -e "${YELLOW}→ Modo: Target externo${NC}"
            echo ""
            echo -ne "  Introduce la URL del objetivo (ej: http://localhost:8080): "
            read -r TARGET_URL

            if [ -z "$TARGET_URL" ]; then
                echo -e "${RED}✗ URL vacía. Abortando.${NC}"
                exit 1
            fi

            echo -ne "  ¿Abrir el dashboard en el navegador al finalizar? [S/n]: "
            read -r BROWSER
            BROWSER_FLAG=""
            if [[ "$BROWSER" =~ ^[Nn]$ ]]; then
                BROWSER_FLAG="--no-browser"
            fi

            echo ""
            python main.py --target "$TARGET_URL" $BROWSER_FLAG
            ;;

        3)
            echo -e "${YELLOW}Saliendo.${NC}"
            exit 0
            ;;

        *)
            echo -e "${RED}✗ Opción no válida. Ejecuta ./run.sh de nuevo.${NC}"
            exit 1
            ;;
    esac
fi

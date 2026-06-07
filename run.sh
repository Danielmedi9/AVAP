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
echo -e "${BLUE}        AVAP - VULNERABILITY ANALYSIS PIPELINE${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo ""

if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}Python not found. Install Python 3.11+ from https://python.org${NC}"
    exit 1
fi
echo -e "${GREEN}Python: $($PYTHON --version 2>&1)${NC}"

if ! command -v docker &>/dev/null; then
    echo -e "${RED}Docker not found. Install Docker Desktop from https://docker.com${NC}"
    exit 1
fi
if ! docker info &>/dev/null 2>&1; then
    echo -e "${RED}Docker is not running. Start Docker Desktop and try again.${NC}"
    exit 1
fi
echo -e "${GREEN}Docker is running${NC}"

if [ ! -d "venv" ]; then
    echo -e "${YELLOW} Creating virtual environment...${NC}"
    $PYTHON -m venv venv
    echo -e "${GREEN}Virtual environment created${NC}"
fi

if [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
elif [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo -e "${RED}Could not find the venv activation script.${NC}"
    exit 1
fi
echo -e "${GREEN}Virtual environment activated${NC}"

echo -e "${YELLOW} Installing dependencies...${NC}"
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "${GREEN}Dependencies installed${NC}"

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo ""

if [ $# -gt 0 ]; then
    echo -e "${CYAN} Running with arguments: $@${NC}"
    echo ""
    python main.py "$@"
else
    echo -e "${BOLD}  What do you want to scan?${NC}"
    echo ""
    echo -e "  ${CYAN}1)${NC} OWASP Juice Shop ${YELLOW}(Docker test environment)${NC}"
    echo -e "     Starts Juice Shop automatically and scans it."
    echo -e "     Includes: Nmap + ZAP + Trivy"
    echo ""
    echo -e "  ${CYAN}2)${NC} External target ${YELLOW}(your own application)${NC}"
    echo -e "     Scans a URL that is already running."
    echo -e "     Includes: Nmap + ZAP"
    echo ""
    echo -e "  ${CYAN}3)${NC} Exit"
    echo ""
    echo -ne "  ${BOLD}Choose an option [1/2/3]:${NC} "
    read -r OPCION

    echo ""

    case "$OPCION" in
        1)
            echo -e "${YELLOW} Mode: OWASP Juice Shop${NC}"
            echo ""

            echo -ne "  Open the dashboard in the browser after finishing? [Y/n]: "
            read -r BROWSER
            BROWSER_FLAG=""
            if [[ "$BROWSER" =~ ^[Nn]$ ]]; then
                BROWSER_FLAG="--no-browser"
            fi

            echo ""
            python main.py --juice-shop $BROWSER_FLAG
            ;;

        2)
            echo -e "${YELLOW} Mode: External target${NC}"
            echo ""
            echo -ne "  Enter the target URL (e.g. http://localhost:8080): "
            read -r TARGET_URL

            if [ -z "$TARGET_URL" ]; then
                echo -e "${RED} Empty URL. Aborting.${NC}"
                exit 1
            fi

            echo -ne "  Open the dashboard in the browser after finishing? [Y/n]: "
            read -r BROWSER
            BROWSER_FLAG=""
            if [[ "$BROWSER" =~ ^[Nn]$ ]]; then
                BROWSER_FLAG="--no-browser"
            fi

            echo ""
            python main.py --target "$TARGET_URL" $BROWSER_FLAG
            ;;

        3)
            echo -e "${YELLOW}Exiting.${NC}"
            exit 0
            ;;

        *)
            echo -e "${RED} Invalid option. Run ./run.sh again.${NC}"
            exit 1
            ;;
    esac
fi

#!/bin/bash

# Colores
rojo='\033[1;31m'
verde='\033[1;32m'
amarillo='\033[1;33m'
azul='\033[1;34m'
magenta='\033[1;35m'
cyan='\033[1;36m'
negro='\033[0;30m'
gris_claro='\033[0;37m'
blanco='\033[1;37m'
endColour='\033[0m'

# Ctrl+C
function ctrl_c(){
    echo -e "\n\n${rojo}[!] Saliendo...${endColour}\n"
    rm -f /tmp/*.tmp
    tput cnorm; exit 1
}
trap ctrl_c INT
tput civis

function show_banner() {
    echo -e "${cyan}"
    echo "  _         ___                      "
    echo " |_) _  __|_ | ._  _._  _  __|_ _ ._ "
    echo " | \(_)(_)|__|_| |_>|_)(/_(_ |_(_)|  "
    echo -e "                    |   ${rojo}Anonymous17  "
    echo -e "${endColour}"
}

#############################
# FUNCIONES DE INFORME
#############################

function section(){
    echo -e "\n${amarillo}[+] $1${endColour}"
}
function result(){
    echo -e "${verde}    -> ${azul}$1${endColour}"
}
function no_result(){
    echo -e "${verde}    -> ${rojo}No encontrado${endColour}"
}

#############################
# FUNCIONES DE ESCANEO
#############################

function check_sudo() {
    section "Permisos sudo disponibles (${rojo}-l${amarillo}):"

    output=$(sudo -n -l 2>/dev/null)

    if [[ -z "$output" ]]; then
        echo -e "${cyan}    -> ${rojo}No se pudieron obtener los permisos sudo${endColour}"
        echo -e "${cyan}       ${rojo}Requiere contraseña o no se tiene acceso${endColour}"
        return
    fi

    tiene_all_all=false

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        clean_line="$(echo "$line" | sed 's/^[ \t]*//')"

        # Filtrar líneas irrelevantes
        if [[ "$clean_line" =~ ^Matching\ Defaults ]] || 
           [[ "$clean_line" =~ ^Runas\ and ]] || 
           [[ "$clean_line" =~ ^User.*may\ run.*commands ]]; then
            continue
        fi

        # Colorear partes importantes
        coloreada="${clean_line//Defaults!/${azul}Defaults!${magenta}}"
        coloreada="${coloreada//secure_path=/${azul}secure_path=${magenta}}"
        coloreada="${coloreada//env_keep+=/${azul}env_keep+=${magenta}}"
        coloreada="${coloreada//includedir/${azul}includedir${magenta}}"
        coloreada="${coloreada//(ALL) ALL/${rojo}(ALL) ALL${magenta}}"
        coloreada="${coloreada//(ALL)/${rojo}(ALL)${verde}}"
        coloreada="${coloreada//NOPASSWD:/${rojo}NOPASSWD:${verde}}"

        # ¿El usuario puede hacer todo como root?
        if [[ "$clean_line" =~ ^\(ALL\)\s+ALL ]]; then
            tiene_all_all=true
        fi

        # Detectar si el usuario puede ejecutar todo como root
        if [[ "$clean_line" =~ ^\([^\)]+\)[[:space:]]+ALL ]]; then
            echo -e "${amarillo}    - ${rojo}$clean_line${endColour}"
            echo -e "${verde}    -> ${rojo}El usuario puede ejecutar cualquier comando como root.${endColour}"
            tiene_all_all=true
            continue
        fi

        echo -e "    ${amarillo}- ${magenta}$coloreada ${endColour}"
    done <<< "$output"
}

function SystemInfo() {
    echo -e "${amarillo}\n[+] Información del sistema:${endColour}"

    ## -> Distro
    distro=$(grep -w "PRETTY_NAME" /etc/os-release | cut -d= -f2 | tr -d '"')
    version=$(grep -w "VERSION_ID" /etc/os-release | cut -d= -f2 | tr -d '"')
    build_id=$(grep -w "BUILD_ID" /etc/os-release | cut -d= -f2 | tr -d '"')
    echo -e "${cyan}    ->${azul} Sistema: ${amarillo}$distro${azul}, Versión: ${rojo}${version:-None}${azul}, Build ID: ${amarillo}${build_id:-none}${endColour}"

    ## -> Interfaces de red
    echo -e "${cyan}    ->${azul} Interfaces de red:${endColour}"
    bina=$(which "ip" 2>/dev/null)
    if [[ -n "$bina" ]]; then
        ip -o -4 addr show 2>/dev/null | while read -r line; do
            iface=$(echo "$line" | awk '{print $2}')
            addr=$(echo "$line" | awk '{print $4}')
            echo -e "${amarillo}        - Interface ${azul}$iface${amarillo} w/ address ${azul}$addr"
        done
    else
        bina=$(which "ifconfig" 2>/dev/null)
        if [[ -n "$bina" ]]; then
            echo -e "        ${amarillo}- ${rojo}Ocurrio un error! ${amarillo}(${magenta}comando ${verde}ip${magenta} no disponible${amarillo})${endColour}"
            echo -e "        ${amarillo}- ${amarillo}Comando ${verde}ifconfig ${amarillo} disponible (${magenta}usar manualmente${amarillo})${endColour}"
        else
            echo -e "        ${amarillo}- ${rojo}Ocurrio un error! ${amarillo}(${magenta}comandos ${verde}ip${magenta} e ${verde}ifconfig${magenta} no disponibles${amarillo})${endColour}"
        fi
    fi

    ## -> Kernel
    kernel=$(uname -r)
    arch=$(uname -m)
    echo -e "${cyan}    ->${azul} Versión del kernel:${endColour}"
    echo -e "${amarillo}        - Running Linux kernel ${azul}$kernel${endColour}"
    echo -e "${amarillo}        - ${azul}$arch${amarillo} processor${endColour}"

    ## -> Nombre del equipo
    hostname=$(hostname)
    echo -e "${cyan}    ->${azul} Nombre del equipo:${endColour} ${amarillo}$hostname${endColour}"
}

function check_suid(){
    section "Archivos ${rojo}SUID${amarillo} con propietario ${rojo}root${amarillo}:"
    find / -perm -4000 -user root 2>/dev/null | xargs ls -l | awk '{print $1 " → " $NF}' | while read -r archivo; do
        coloreada="${archivo//→/${rojo}→${magenta}}"
        echo -e "${verde}    |${azul} $coloreada ${endColour}"
    done
}

function check_capabilities(){
    section "Binarios con capacidades asignadas:"
    if command -v getcap &>/dev/null; then
        binarios_con_capas=$(getcap -r / 2>/dev/null | awk '{print $1 " → " $NF}')
        if [[ -n "$binarios_con_capas" ]]; then
            echo "$binarios_con_capas" | while read -r capas; do
                coloreada="${capas//→/${rojo}→${magenta}}"
                coloreada="${coloreada//=/${magenta}=${rojo}}"
                echo -e "${verde}    |${azul} $coloreada ${endColour}"
            done
        else
            echo -e "${verde}    -> ${rojo}No hay binarios con capacidades asignadas.${endColour}"
        fi
    else
        echo -e "${verde}    -> ${rojo}getcap no está instalado.${endColour}"
    fi
}

function check_sensitive_files() {
    section "Archivos sensibles:"

    files=(
        "/etc/shadow"
        "/etc/passwd"
        "$HOME/.bash_history"
        "$HOME/.bashrc"
        "$HOME/.zsh_history"
        "$HOME/.zshrc"
        "$HOME/.python_history"
        "$HOME/.env"
        "$HOME/.gitconfig"
        "$HOME/.profile"
        "$HOME/.python_history"
        "$HOME/.ssh/id_rsa"
        "$HOME/.ssh/id_dsa"
        "$HOME/.ssh/id_ecdsa"
        "$HOME/.ssh/id_ed25519"
        "$HOME/.ssh/id_rsa.pub"
        "$HOME/.ssh/known_hosts"
        "$HOME/.gnupg/secring.gpg"
        "$HOME/.gnupg/private-keys-v1.d"
        "$HOME/.gnupg/pubring.kbx"
        "$HOME/.netrc"
        "$HOME/.aws/credentials"
        "$HOME/.config/gcloud/credentials.db"
    )

    for file in "${files[@]}"; do
        if [ -e "$file" ]; then
            if [ -r "$file" ]; then
                echo -e "${verde}    -> ${azul}$file (${magenta}legible${azul})${endColour}"
            else
                echo -e "${verde}    -> ${azul}$file (${rojo}no legible${azul})${endColour}"
            fi
        fi
    done
}

function check_users(){
    section "Usuarios interesantes en el sistema:"
    contador=0
    cat /etc/passwd | grep sh | sed 's/:/ /g' | awk '{print $1 " → " $NF}' | while read -r user; do
        coloreada="${user//→/${rojo}→${magenta}}"
        contador=$((contador+1))
        echo -e "${verde}    $contador${azul} $coloreada ${endColour}"
    done
}

function check_common_bins(){
    section "Binarios útiles presentes en el sistema:"

    local bins=("awk" "docker" "find" "gcc" "less" "more" "nmap" "perl" "python" "socat" "tee" "vim" "vi" "lsb_release" "php" "nano")
    local found=false

    for bin in "${bins[@]}"; do
        bin_path=$(which "$bin" 2>/dev/null)
        if [[ -n "$bin_path" ]]; then
            echo -e "    ${amarillo}- ${azul}${bin}${rojo} → ${magenta}${bin_path}${endColour}"
            found=true
        fi
    done

    if [ "$found" = false ]; then
        echo -e "${verde}    ->${rojo} No se encontró ninguno binario util.${endColour}"
    fi
}

function check_user(){
    if [ "$EUID" -eq 0 ]; then
        result "¡Eres root!\n"
        tput cnorm; exit 0
    else
        uid=$(id -u)
        gid=$(id -g)
        user=$(whoami)
        
        echo -e "${amarillo}[+] Usuario actual: ${azul}$user${endColour}"
        echo -e "${amarillo}[+] Grupos añadidos:${endColour}"
        echo -e "    ${verde}-> ${azul}uid=${uid}(${magenta}${user}${azul}) gid=${gid}(${magenta}${user}${azul})${endColour} ${azul}grupos=${endColour}"

        # Obtener grupos completos
        grupos_full=$(id -Gn)       # Nombres de grupo
        grupos_ids=$(id -G)         # IDs de grupo

        # Convertir a arrays
        IFS=' ' read -ra nombres_array <<< "$grupos_full"
        IFS=' ' read -ra ids_array <<< "$grupos_ids"

        # Mostrar en bloques de 3
        line="       "
        for i in "${!ids_array[@]}"; do
            if [[ ${nombres_array[$i]} == "sudo" || ${nombres_array[$i]} == "wheel" ]]; then
                line+="${azul}${ids_array[$i]}${endColour}(${rojo}${nombres_array[$i]}${endColour}), "
            else
                line+="${azul}${ids_array[$i]}${endColour}(${magenta}${nombres_array[$i]}${endColour}), "
            fi
            # Cada 3 grupos, imprimir línea
            if (( (i + 1) % 3 == 0 )); then
                echo -e "${line%, }"
                line="       "
            fi
        done

        if [[ "$line" != "      " ]]; then
            echo -e "${line%, }"
        fi
    fi
}

#############################
# EJECUCIÓN DEL INFORME
#############################

function main(){
    show_banner
    check_user
    SystemInfo
    check_sudo
    check_users
    check_sensitive_files
    check_common_bins
    check_capabilities
    check_suid
    echo -e "\n${amarillo}[+] Análisis completado.${endColour}\n"
    rm -f /tmp/*.tmp
    tput cnorm
}

main

#!/bin/bash
# ==============================================================================
# Script: merge_and_run_zeek_unsw.sh (Versión ultra-rápida paralela en RAM)
# ==============================================================================

# 1. Definición de rutas base
BASE_DIR="/mnt/c/Users/gemma/Desktop/TFG_GemmaBeatrizVate/UNSW-IoTraffic"
PCAP_DIR="$BASE_DIR/pcaps"
ZEEK_LOGS_DIR="$BASE_DIR/1_Data/zeek_logs/logs"
ZEEK_JA4_LOAD="$BASE_DIR/0_Init/ja4/zeek/__load__.zeek"

# Directorio de trabajo en memoria RAM (RAM disk)
RAM_WORK_DIR="/dev/shm/zeek_unsw_work"

# Detección de núcleos disponibles para paralelizar
CORES=$(nproc)
echo "=== Procesando capturas PCAP con Zeek en paralelo ($CORES núcleos) ==="

# 2. Comprobaciones y preparación
if [ ! -f "$ZEEK_JA4_LOAD" ]; then
    echo "[!] Error: No se encuentra $ZEEK_JA4_LOAD"
    exit 1
fi

rm -rf "$ZEEK_LOGS_DIR" "$RAM_WORK_DIR"
mkdir -p "$ZEEK_LOGS_DIR"
mkdir -p "$RAM_WORK_DIR"

# 3. Función auxiliar ejecutada en paralelo por cada PCAP
process_single_pcap() {
    local pcap="$1"
    local ja4_load="$2"
    local ram_dir="$3"
    
    local pcap_name
    pcap_name=$(basename "$pcap")
    local out_dir="$ram_dir/$pcap_name"
    mkdir -p "$out_dir"
    
    echo "[+] Procesando en RAM: $pcap_name"
    # Añadido -C para ignorar checksums inválidos por offloading
    zeek -C -r "$pcap" "$ja4_load" Log::default_logdir="$out_dir"
}

export -f process_single_pcap

# 4. Procesamiento paralelo con xargs
find "$PCAP_DIR" -type f \( -name "*.pcap" -o -name "*.pcapng" \) | \
    xargs -P "$CORES" -I {} bash -c "process_single_pcap '{}' '$ZEEK_JA4_LOAD' '$RAM_WORK_DIR'"

echo "=== Consolidando logs de Zeek en disco ==="

# 5. Fusión rápida de logs por tipo (conn.log, ssl.log, x509.log, etc.)
first_folder=true
for dev_dir in "$RAM_WORK_DIR"/*; do
    [ -d "$dev_dir" ] || continue
    
    if [ "$first_folder" = true ]; then
        # Copiar todos los logs iniciales manteniendo cabeceras
        for log_file in "$dev_dir"/*.log; do
            [ -f "$log_file" ] || continue
            cp "$log_file" "$ZEEK_LOGS_DIR/$(basename "$log_file")"
        done
        first_folder=false
    else
        # Concatenar únicamente los datos (excluyendo cabeceras '#')
        for log_file in "$dev_dir"/*.log; do
            [ -f "$log_file" ] || continue
            target_log="$ZEEK_LOGS_DIR/$(basename "$log_file")"
            if [ -f "$target_log" ]; then
                grep -v '^#' "$log_file" >> "$target_log"
            else
                cp "$log_file" "$target_log"
            fi
        done
    fi
done

# 6. Limpieza de memoria RAM
rm -rf "$RAM_WORK_DIR"

echo "[✔] Logs consolidados generados con éxito en: $ZEEK_LOGS_DIR"
ls -lh "$ZEEK_LOGS_DIR"
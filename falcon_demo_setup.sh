#!/bin/bash
# ============================================================
#  FALCON DEMO -- SETUP SCRIPT
#  Prepare tous les fichiers necessaires sur Kali
#  Usage: bash falcon_demo_setup.sh
# ============================================================

DEMO_DIR="/root/falcon_demo"
KALI_IP="10.0.2.100"

echo ""
echo "============================================="
echo "  FALCON ENCOUNTER DEMO -- SETUP"
echo "============================================="

# Creer la structure
mkdir -p $DEMO_DIR/{www,results,logs}

# Copier les fichiers RC
cp falcon_demo_full.rc     $DEMO_DIR/
cp post_exploit_full.rc    $DEMO_DIR/
cp edr_master_suite.ps1    $DEMO_DIR/
cp attack_chain.ps1        $DEMO_DIR/www/
cp follina.ps1             $DEMO_DIR/www/
cp edr_master_suite.ps1    $DEMO_DIR/www/

# Linker AutoRunScript dans le RC principal
sed -i "s|# set AutoRunScript|set AutoRunScript|g" $DEMO_DIR/falcon_demo_full.rc

echo "[+] Files copied to $DEMO_DIR"
echo ""
echo "  Structure:"
find $DEMO_DIR -type f | sort | sed 's/^/  /'
echo ""
echo "============================================="
echo "  LAUNCH:"
echo "  msfconsole -r $DEMO_DIR/falcon_demo_full.rc"
echo "============================================="

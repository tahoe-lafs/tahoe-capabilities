nodedir=$1
shift

datafile=$(mktemp)

for i in $(seq 10); do
    echo "Hello world" >> "$datafile"
done

chk=$(tahoe -d "$nodedir" put --format=CHK "$datafile")
chk_json=$(tahoe -d "$nodedir" ls --json $chk)
chk_verify=$(echo "$chk_json" | jp --unquoted '[1].verify_uri')

ssk=$(tahoe -d "$nodedir" put --format=SDMF "$datafile")
ssk_json=$(tahoe -d "$nodedir" ls --json $ssk)
ssk_ro=$(echo "$ssk_json" | jp --unquoted '[1].ro_uri')
ssk_verify=$(echo "$ssk_json" | jp --unquoted '[1].verify_uri')

ssk_dir2=$(tahoe -d "$nodedir" mkdir --format=SDMF)
ssk_dir2_json=$(tahoe -d "$nodedir" ls --json $ssk_dir2)
ssk_dir2_ro=$(echo "$ssk_dir2_json" | jp --unquoted '[1].ro_uri')
ssk_dir2_verify=$(echo "$ssk_dir2_json" | jp --unquoted '[1].verify_uri')

mdmf=$(tahoe -d "$nodedir" put --format=MDMF "$datafile")
mdmf_json=$(tahoe -d "$nodedir" ls --json $mdmf)
mdmf_ro=$(echo "$mdmf_json" | jp --unquoted '[1].ro_uri')
mdmf_verify=$(echo "$mdmf_json" | jp --unquoted '[1].verify_uri')

mdmf_dir2=$(tahoe -d "$nodedir" mkdir --format=MDMF)
mdmf_dir2_json=$(tahoe -d "$nodedir" ls --json $mdmf_dir2)
mdmf_dir2_ro=$(echo "$mdmf_dir2_json" | jp --unquoted '[1].ro_uri')
mdmf_dir2_verify=$(echo "$mdmf_dir2_json" | jp --unquoted '[1].verify_uri')

cat <<EOF
 CHK = "$chk"
 CHK_VERIFY = "$chk_verify"

 # TODO: Hard to make CHK:DIR2: from CLI.

 SSK = "$ssk"
 SSK_RO = "$ssk_ro"
 SSK_VERIFY: "$ssk_verify"

 SSK_DIR2 = "$ssk_dir2"
 SSK_DIR2_RO = "$ssk_dir2_ro"
 SSK_DIR2_VERIFY = "$ssk_dir2_verify"

 MDMF = "$mdmf"
 MDMF_RO = "$mdmf_ro"
 MDMF_VERIFY = "$mdmf_verify"

 MDMF_DIR2 = "$mdmf_dir2"
 MDMF_DIR2_RO = "$mdmf_dir2_ro"
 MDMF_DIR2_VERIFY = "$mdmf_dir2_verify"
EOF

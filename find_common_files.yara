rule find_common_files {

 meta:
    author = "Bulanov Gleb"
    date = "09/10/2024"
    version = "1.0"


 strings:
    $rar_header = { 52 61 72 21 1A } // RAR header
    $zip_header = { 50 4B } // ZIP header
    $jpeg_header = { FF D8 FF } // JPEG header
    $mp3_header = { 49 44 33 } // MP3 header

 condition:
    $rar_header or $zip_header or $jpeg_header or $mp3_header
}

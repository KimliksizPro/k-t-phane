import shutil
import os

fonts = [
    ("arial.ttf", "arial.ttf"),
    ("arialbd.ttf", "arialbd.ttf"),
    ("ariali.ttf", "ariali.ttf"),
    ("arialbi.ttf", "arialbi.ttf")
]

source_dir = r"C:\Windows\Fonts"
dest_dir = r"static\fonts"

if not os.path.exists(dest_dir):
    os.makedirs(dest_dir)

for src_name, dest_name in fonts:
    src_path = os.path.join(source_dir, src_name)
    dest_path = os.path.join(dest_dir, dest_name)
    
    try:
        if os.path.exists(src_path):
            shutil.copy2(src_path, dest_path)
            print(f"Success: Copied {src_name}")
        else:
            print(f"Error: {src_name} not found in Windows Fonts")
    except Exception as e:
        print(f"Error copying {src_name}: {e}")

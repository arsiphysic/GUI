from PIL import Image
import sys

# Usage: python create_icon.py input.png output.ico
if len(sys.argv) < 3:
    print("Usage: python create_icon.py input.png output.ico")
    sys.exit(1)

src = sys.argv[1]
dst = sys.argv[2]

img = Image.open(src)
# Save multiple sizes for better results on Windows
img.save(dst, sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)])
print(f"Saved {dst}")
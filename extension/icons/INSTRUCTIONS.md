# Icon Generation Instructions

The extension requires PNG icon files. You have 3 options:

## Option 1: Use the HTML Generator (Easiest)

1. Open `create-icons.html` (in extension folder) in your browser
2. Click the 3 download links to get:
   - icon16.png
   - icon48.png
   - icon128.png
3. Save all 3 files to the `extension/icons/` folder

## Option 2: Use ImageMagick (Command Line)

```bash
cd extension/icons
convert icon.svg -resize 16x16 icon16.png
convert icon.svg -resize 48x48 icon48.png
convert icon.svg -resize 128x128 icon128.png
```

## Option 3: Use an Online Converter

1. Go to https://cloudconvert.com/svg-to-png
2. Upload `icon.svg`
3. Convert to PNG at sizes: 16x16, 48x48, 128x128
4. Download and rename to icon16.png, icon48.png, icon128.png
5. Place in `extension/icons/` folder

## Option 4: Extension Will Work Without Custom Icons

The extension will work with default Chrome icons if you skip this step.
The functionality is not affected, only the visual appearance.

# Build Windows Executable using GitHub Actions (Free!)

GitHub Actions will build your Windows .exe file automatically in the cloud - no Windows machine needed!

## Quick Setup (5 minutes)

### Step 1: Create GitHub Repository

1. Go to https://github.com/new
2. Repository name: `email-metadata-checker` (or any name)
3. Make it **Public** or **Private** (your choice)
4. Click "Create repository"

### Step 2: Upload Files

Upload these files to your new repository:

**Required files:**
- `email_metadata_checker.py`
- `requirements.txt`
- `.github/workflows/build-windows.yml`

**Optional files:**
- `README_EMAIL_CHECKER.md`
- `EmailMetadataChecker.spec`

**How to upload:**

**Option A: Using GitHub Web Interface**
1. Click "uploading an existing file"
2. Drag and drop all files
3. Click "Commit changes"

**Option B: Using Git Command Line**
```bash
cd /Users/ishitkaroli/Downloads/Scripts

# Initialize git (if not already)
git init
git add email_metadata_checker.py requirements.txt .github/
git commit -m "Initial commit"

# Add your GitHub repo as remote
git remote add origin https://github.com/YOUR_USERNAME/email-metadata-checker.git

# Push to GitHub
git branch -M main
git push -u origin main
```

### Step 3: Wait for Build

1. Go to your repository on GitHub
2. Click on "Actions" tab
3. You'll see "Build Windows Executable" workflow running
4. Wait 2-3 minutes for it to complete

### Step 4: Download Your .exe

1. When build is complete (green checkmark ✓)
2. Click on the workflow run
3. Scroll down to "Artifacts"
4. Click "EmailMetadataChecker-Windows" to download
5. Extract the ZIP file
6. You now have `EmailMetadataChecker.exe`!

## Manual Trigger

To build anytime without pushing code:

1. Go to "Actions" tab
2. Click "Build Windows Executable"
3. Click "Run workflow" button
4. Select "main" branch
5. Click green "Run workflow" button

## File Locations

After successful build, download from:
- **Artifacts section** (bottom of workflow page)
- Available for 90 days
- ~50-60 MB file

## Troubleshooting

### Build fails with "Python module not found"

Edit `.github/workflows/build-windows.yml` and add the missing module:
```yaml
pip install dnspython python-whois requests MISSING_MODULE_HERE
```

### Want smaller file size?

Edit the workflow file and add `--upx-dir` flag:
```yaml
pyinstaller --onefile --upx-dir /path/to/upx --name EmailMetadataChecker
```

### Build works but .exe doesn't run

This usually means a dependency is missing. Add hidden imports to the build command:
```yaml
pyinstaller --onefile --hidden-import dns.resolver --hidden-import whois --name EmailMetadataChecker email_metadata_checker.py
```

## Cost

GitHub Actions is **100% FREE** for public repositories and includes:
- 2,000 minutes/month for private repos (more than enough)
- Unlimited for public repos

## Next Steps

Once you have the .exe file:

1. **Test it:**
   - Copy to a Windows machine
   - Double-click to run
   - Enter a domain to analyze

2. **Distribute it:**
   - Share the .exe file directly
   - Or create a GitHub Release (see below)

## Create a Release (Recommended)

To make the .exe easily downloadable:

1. Go to your repository
2. Click "Releases" (right sidebar)
3. Click "Create a new release"
4. Tag version: `v1.0.0`
5. Release title: `Email Metadata Checker v1.0`
6. Upload your `EmailMetadataChecker.exe`
7. Click "Publish release"

Now anyone can download from the Releases page!

## Auto-Release on Tag

To automatically build and release when you create a tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The workflow will build and attach the .exe to the release automatically!

---

**Need help?** The workflow file is already configured and ready to use!

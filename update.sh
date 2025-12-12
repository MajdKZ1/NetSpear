#!/bin/bash

################################################################################
# NetSpear Update Script
# Updates NetSpear to the latest version from GitHub repository
# 
# Repository: https://github.com/MajdKZ1/NetSpear.git
# © 2025 OpenNET LLC - All Rights Reserved
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# NetSpear Purple
NETSPEAR_PURPLE='\033[38;2;122;6;205m'

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="https://github.com/MajdKZ1/NetSpear.git"

# Banner
print_banner() {
    echo -e "${NETSPEAR_PURPLE}"
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│              NETSPEAR UPDATE SCRIPT v2.0                    │"
    echo "│              © 2025 OpenNET LLC - All Rights Reserved       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

# Print colored message
print_info() {
    echo -e "${CYAN}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    if ! command_exists git; then
        print_error "Git is not installed. Please install git first."
        echo "  Debian/Ubuntu: sudo apt install git"
        echo "  macOS: brew install git"
        echo "  Arch Linux: sudo pacman -S git"
        exit 1
    fi
    
    print_success "Git is installed"
}

# Check if we're in a git repository
check_git_repo() {
    print_info "Checking if this is a git repository..."
    
    if [ ! -d "$SCRIPT_DIR/.git" ]; then
        print_warning "Not a git repository. Initializing..."
        
        cd "$SCRIPT_DIR"
        git init
        git remote add origin "$REPO_URL" 2>/dev/null || git remote set-url origin "$REPO_URL"
        print_success "Git repository initialized"
        return 1  # Return 1 to indicate fresh init
    fi
    
    print_success "Git repository found"
    return 0
}

# Check remote URL
check_remote() {
    print_info "Checking remote repository..."
    
    cd "$SCRIPT_DIR"
    
    # Check if remote exists
    if ! git remote get-url origin >/dev/null 2>&1; then
        print_warning "No remote origin found. Adding remote..."
        git remote add origin "$REPO_URL"
        print_success "Remote added: $REPO_URL"
    else
        CURRENT_REMOTE=$(git remote get-url origin)
        if [ "$CURRENT_REMOTE" != "$REPO_URL" ]; then
            print_warning "Remote URL mismatch. Updating..."
            git remote set-url origin "$REPO_URL"
            print_success "Remote URL updated to: $REPO_URL"
        else
            print_success "Remote repository verified: $REPO_URL"
        fi
    fi
}

# Backup uncommitted changes
backup_changes() {
    cd "$SCRIPT_DIR"
    
    if ! git diff --quiet || ! git diff --cached --quiet; then
        print_warning "Uncommitted changes detected. Creating backup..."
        
        BACKUP_DIR="$SCRIPT_DIR/.update_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        
        # Create a patch of uncommitted changes
        git diff > "$BACKUP_DIR/uncommitted_changes.patch" 2>/dev/null || true
        git diff --cached > "$BACKUP_DIR/staged_changes.patch" 2>/dev/null || true
        
        # Store current branch and commit
        git rev-parse HEAD > "$BACKUP_DIR/previous_commit.txt" 2>/dev/null || true
        git branch --show-current > "$BACKUP_DIR/previous_branch.txt" 2>/dev/null || true
        
        print_success "Backup created in: $BACKUP_DIR"
        echo "  You can restore changes using: git apply $BACKUP_DIR/uncommitted_changes.patch"
    fi
}

# Stash uncommitted changes
stash_changes() {
    cd "$SCRIPT_DIR"
    
    if ! git diff --quiet || ! git diff --cached --quiet; then
        print_warning "Stashing uncommitted changes..."
        git stash push -m "NetSpear update stash $(date +%Y%m%d_%H%M%S)" || true
        print_success "Changes stashed (use 'git stash pop' to restore)"
        return 0
    fi
    return 1
}

# Fetch updates
fetch_updates() {
    print_info "Fetching latest updates from repository..."
    
    cd "$SCRIPT_DIR"
    
    # Fetch from remote
    if git fetch origin main 2>&1 | while IFS= read -r line; do
        echo -e "${BLUE}    $line${NC}"
    done; then
        print_success "Updates fetched successfully"
        return 0
    else
        print_error "Failed to fetch updates"
        return 1
    fi
}

# Show what will be updated
show_changes() {
    cd "$SCRIPT_DIR"
    
    CURRENT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    REMOTE_COMMIT=$(git rev-parse origin/main 2>/dev/null || echo "unknown")
    
    if [ "$CURRENT_COMMIT" = "$REMOTE_COMMIT" ] && [ "$CURRENT_COMMIT" != "unknown" ]; then
        print_success "Already up to date! (Commit: ${CURRENT_COMMIT:0:8})"
        return 1  # No update needed
    fi
    
    print_info "Changes to be applied:"
    echo ""
    
    if [ "$CURRENT_COMMIT" != "unknown" ] && [ "$REMOTE_COMMIT" != "unknown" ]; then
        git log --oneline "$CURRENT_COMMIT..origin/main" 2>/dev/null | head -10 | while IFS= read -r line; do
            echo -e "  ${GREEN}→${NC} $line"
        done
        
        COMMIT_COUNT=$(git rev-list --count "$CURRENT_COMMIT..origin/main" 2>/dev/null || echo "?")
        echo ""
        print_info "Total commits to pull: $COMMIT_COUNT"
    else
        print_warning "Cannot determine changes (this may be a fresh clone)"
    fi
    
    echo ""
    return 0
}

# Perform update
perform_update() {
    cd "$SCRIPT_DIR"
    
    CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "main")
    
    print_info "Updating to latest version..."
    echo ""
    
    # Checkout main branch if not already on it
    if [ "$CURRENT_BRANCH" != "main" ]; then
        print_info "Switching to main branch..."
        git checkout main 2>/dev/null || git checkout -b main origin/main
    fi
    
    # Reset to remote (this ensures clean update)
    print_info "Applying updates..."
    
    if git reset --hard origin/main; then
        print_success "Code updated successfully"
        
        # Clean untracked files (optional, can be commented out)
        # git clean -fd
    else
        print_error "Failed to update code"
        return 1
    fi
}

# Update dependencies
update_dependencies() {
    print_info "Checking Python dependencies..."
    
    if command_exists pip3; then
        if [ -f "$SCRIPT_DIR/NetSpear/requirements.txt" ]; then
            print_info "Updating Python dependencies..."
            pip3 install -q --upgrade -r "$SCRIPT_DIR/NetSpear/requirements.txt" 2>&1 | while IFS= read -r line; do
                echo -e "${BLUE}    $line${NC}"
            done
            print_success "Dependencies updated"
        else
            print_warning "requirements.txt not found, skipping dependency update"
        fi
    else
        print_warning "pip3 not found, skipping dependency update"
    fi
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    if [ -f "$SCRIPT_DIR/NetSpear/main.py" ]; then
        VERSION=$(grep -oP "v\d+\.\d+" "$SCRIPT_DIR/NetSpear/main.py" | head -1 || echo "unknown")
        print_success "NetSpear installation verified (Version: $VERSION)"
        return 0
    else
        print_error "Installation verification failed - main.py not found"
        return 1
    fi
}

# Main function
main() {
    clear
    print_banner
    
    print_info "Starting NetSpear update process..."
    echo ""
    
    # Check prerequisites
    check_prerequisites
    echo ""
    
    # Check git repository
    if ! check_git_repo; then
        print_warning "This appears to be a fresh installation."
        print_info "Pulling latest code from repository..."
        cd "$SCRIPT_DIR"
        git pull origin main || git fetch origin main && git reset --hard origin/main
        echo ""
        verify_installation
        echo ""
        print_success "Update complete! You can now run NetSpear."
        exit 0
    fi
    echo ""
    
    # Check remote
    check_remote
    echo ""
    
    # Backup changes
    backup_changes
    echo ""
    
    # Stash changes
    STASHED=0
    if stash_changes; then
        STASHED=1
    fi
    echo ""
    
    # Fetch updates
    if ! fetch_updates; then
        if [ $STASHED -eq 1 ]; then
            print_info "Restoring stashed changes..."
            git stash pop || true
        fi
        exit 1
    fi
    echo ""
    
    # Show changes
    if ! show_changes; then
        if [ $STASHED -eq 1 ]; then
            print_info "Restoring stashed changes..."
            git stash pop || true
        fi
        echo ""
        print_success "NetSpear is already up to date!"
        exit 0
    fi
    echo ""
    
    # Confirm update
    read -p "$(echo -e ${YELLOW}Do you want to continue with the update? [y/N]: ${NC})" -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Update cancelled by user"
        if [ $STASHED -eq 1 ]; then
            print_info "Restoring stashed changes..."
            git stash pop || true
        fi
        exit 0
    fi
    echo ""
    
    # Perform update
    if ! perform_update; then
        if [ $STASHED -eq 1 ]; then
            print_info "Restoring stashed changes..."
            git stash pop || true
        fi
        exit 1
    fi
    echo ""
    
    # Restore stashed changes if any
    if [ $STASHED -eq 1 ]; then
        print_warning "Attempting to restore stashed changes..."
        if git stash pop; then
            print_success "Stashed changes restored"
        else
            print_warning "Some conflicts may have occurred. Check with 'git status'"
        fi
        echo ""
    fi
    
    # Update dependencies
    update_dependencies
    echo ""
    
    # Verify installation
    if verify_installation; then
        echo ""
        print_success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        print_success "NetSpear has been successfully updated!"
        print_success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        print_info "You can now run NetSpear using:"
        echo -e "  ${GREEN}python3 NetSpear/main.py${NC}"
        echo ""
    else
        print_error "Update completed but verification failed. Please check the installation."
        exit 1
    fi
}

# Run main function
main


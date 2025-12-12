"""
Custom wordlist management system.
"""
import logging
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone
import json

logger = logging.getLogger(__name__)


class WordlistManager:
    """Manage custom wordlists."""
    
    def __init__(self, wordlist_dir: Optional[Path] = None):
        """
        Initialize wordlist manager.
        
        Args:
            wordlist_dir: Directory for storing wordlists
        """
        if wordlist_dir:
            self.wordlist_dir = Path(wordlist_dir)
        else:
            self.wordlist_dir = Path.home() / ".netspear" / "wordlists"
        
        self.wordlist_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.wordlist_dir / "metadata.json"
        self._load_metadata()
    
    def _load_metadata(self):
        """Load wordlist metadata."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, "r") as f:
                    self.metadata = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load metadata: {e}")
                self.metadata = {}
        else:
            self.metadata = {}
    
    def _save_metadata(self):
        """Save wordlist metadata."""
        try:
            with open(self.metadata_file, "w") as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def create_wordlist(
        self,
        name: str,
        words: List[str],
        description: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Path:
        """
        Create a custom wordlist.
        
        Args:
            name: Wordlist name
            words: List of words
            description: Optional description
            category: Optional category (directory, passwords, usernames, etc.)
            
        Returns:
            Path to created wordlist file
        """
        wordlist_path = self.wordlist_dir / f"{name}.txt"
        
        try:
            with open(wordlist_path, "w") as f:
                f.write("\n".join(words))
            
            # Update metadata
            self.metadata[name] = {
                "name": name,
                "filename": wordlist_path.name,
                "path": str(wordlist_path),
                "word_count": len(words),
                "description": description,
                "category": category,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save_metadata()
            
            logger.info(f"Created wordlist: {name} ({len(words)} words)")
            return wordlist_path
        except Exception as e:
            logger.error(f"Failed to create wordlist: {e}")
            raise
    
    def get_wordlist(self, name: str) -> Optional[Path]:
        """Get wordlist file path by name."""
        if name in self.metadata:
            return Path(self.metadata[name]["path"])
        return None
    
    def list_wordlists(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all wordlists.
        
        Args:
            category: Optional category filter
            
        Returns:
            List of wordlist metadata
        """
        wordlists = list(self.metadata.values())
        if category:
            wordlists = [w for w in wordlists if w.get("category") == category]
        return wordlists
    
    def delete_wordlist(self, name: str) -> bool:
        """Delete a wordlist."""
        if name not in self.metadata:
            return False
        
        try:
            wordlist_path = Path(self.metadata[name]["path"])
            if wordlist_path.exists():
                wordlist_path.unlink()
            del self.metadata[name]
            self._save_metadata()
            logger.info(f"Deleted wordlist: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete wordlist: {e}")
            return False


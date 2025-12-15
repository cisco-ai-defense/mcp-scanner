# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Translation utility for MCP Scanner.

This module provides automatic language detection and translation
for tool descriptions, prompts, and other text content to ensure
accurate security analysis regardless of the source language.
"""

import logging
from typing import Optional, Dict, Any
import os

try:
    import argostranslate.translate
    import argostranslate.package
    ARGOS_AVAILABLE = True
except ImportError:
    ARGOS_AVAILABLE = False

logger = logging.getLogger(__name__)


class TranslationService:
    """Service for detecting and translating non-English text to English.
    
    This service uses Argos Translate for offline translation to ensure
    privacy and avoid external API dependencies. It automatically detects
    the language of input text and translates it to English if needed.
    
    Attributes:
        enabled: Whether translation is enabled
        _initialized: Whether translation packages are initialized
        _translation_cache: Cache of translated texts to avoid redundant translations
    """
    
    def __init__(self, enabled: bool = True):
        """Initialize the translation service.
        
        Args:
            enabled: Whether to enable translation. If False, text is returned as-is.
        """
        self.enabled = enabled and ARGOS_AVAILABLE
        self._initialized = False
        self._translation_cache: Dict[str, str] = {}
        
        if not ARGOS_AVAILABLE and enabled:
            logger.warning(
                "argostranslate not available. Translation disabled. "
                "Install with: pip install argostranslate"
            )
        
        if self.enabled:
            self._initialize()
    
    def _initialize(self):
        """Initialize translation packages if not already done."""
        if self._initialized:
            return
        
        try:
            # Update package index
            logger.info("Initializing translation service...")
            argostranslate.package.update_package_index()
            
            # Get available packages
            available_packages = argostranslate.package.get_available_packages()
            
            # Install packages for common languages to English
            # Priority languages: Spanish, French, German, Chinese, Japanese, Korean, Russian
            priority_langs = ['es', 'fr', 'de', 'zh', 'ja', 'ko', 'ru', 'pt', 'it', 'ar']
            
            installed_count = 0
            for lang_code in priority_langs:
                # Check if package is already installed
                installed_langs = argostranslate.translate.get_installed_languages()
                from_lang = next((l for l in installed_langs if l.code == lang_code), None)
                to_lang = next((l for l in installed_langs if l.code == 'en'), None)
                
                if from_lang and to_lang and from_lang.get_translation(to_lang):
                    continue  # Already installed
                
                # Find and install package
                package = next(
                    (p for p in available_packages 
                     if p.from_code == lang_code and p.to_code == 'en'),
                    None
                )
                
                if package:
                    try:
                        logger.debug(f"Installing translation package: {lang_code} -> en")
                        package.install()
                        installed_count += 1
                    except Exception as e:
                        logger.warning(f"Failed to install {lang_code}->en package: {e}")
            
            if installed_count > 0:
                logger.info(f"Installed {installed_count} translation packages")
            
            self._initialized = True
            logger.info("Translation service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize translation service: {e}")
            self.enabled = False
    
    def detect_language(self, text: str) -> Optional[str]:
        """Detect the language of the given text.
        
        Args:
            text: The text to detect language for
            
        Returns:
            ISO 639 language code (e.g., 'en', 'es', 'fr') or None if detection fails
        """
        if not self.enabled or not text or len(text.strip()) < 10:
            return 'en'  # Assume English for short text
        
        try:
            # Simple heuristic: check if text contains mostly ASCII characters
            ascii_ratio = sum(ord(c) < 128 for c in text) / len(text)
            if ascii_ratio > 0.9:
                return 'en'  # Likely English
            
            # Use argostranslate's language detection if available
            # For now, we'll use a simple approach: try to translate from various languages
            # and see which one produces the most coherent result
            
            # This is a simplified approach - in production, you might want to use
            # a dedicated language detection library like langdetect or fasttext
            installed_langs = argostranslate.translate.get_installed_languages()
            
            # Check for non-ASCII characters that indicate specific languages
            if any('\u4e00' <= c <= '\u9fff' for c in text):
                return 'zh'  # Chinese
            if any('\u3040' <= c <= '\u309f' or '\u30a0' <= c <= '\u30ff' for c in text):
                return 'ja'  # Japanese
            if any('\uac00' <= c <= '\ud7af' for c in text):
                return 'ko'  # Korean
            if any('\u0600' <= c <= '\u06ff' for c in text):
                return 'ar'  # Arabic
            if any('\u0400' <= c <= '\u04ff' for c in text):
                return 'ru'  # Russian
            
            # For European languages, default to Spanish/French/German based on common words
            text_lower = text.lower()
            if any(word in text_lower for word in ['el', 'la', 'los', 'las', 'de', 'que', 'en']):
                return 'es'  # Spanish
            if any(word in text_lower for word in ['le', 'la', 'les', 'de', 'que', 'dans']):
                return 'fr'  # French
            if any(word in text_lower for word in ['der', 'die', 'das', 'und', 'ist', 'von']):
                return 'de'  # German
            
            return 'en'  # Default to English
            
        except Exception as e:
            logger.warning(f"Language detection failed: {e}")
            return 'en'
    
    def translate_to_english(self, text: str, source_lang: Optional[str] = None) -> Dict[str, Any]:
        """Translate text to English if it's in a different language.
        
        Args:
            text: The text to translate
            source_lang: Optional source language code. If None, will be auto-detected.
            
        Returns:
            Dictionary containing:
                - translated_text: The translated text (or original if already English)
                - original_text: The original text
                - source_language: Detected or specified source language
                - was_translated: Boolean indicating if translation occurred
        """
        if not self.enabled or not text:
            return {
                'translated_text': text,
                'original_text': text,
                'source_language': 'en',
                'was_translated': False
            }
        
        # Check cache
        cache_key = f"{source_lang or 'auto'}:{text[:100]}"
        if cache_key in self._translation_cache:
            cached = self._translation_cache[cache_key]
            return {
                'translated_text': cached,
                'original_text': text,
                'source_language': source_lang or 'unknown',
                'was_translated': True
            }
        
        try:
            # Detect language if not provided
            if not source_lang:
                source_lang = self.detect_language(text)
            
            # If already English, return as-is
            if source_lang == 'en':
                return {
                    'translated_text': text,
                    'original_text': text,
                    'source_language': 'en',
                    'was_translated': False
                }
            
            # Get translation
            installed_langs = argostranslate.translate.get_installed_languages()
            from_lang = next((l for l in installed_langs if l.code == source_lang), None)
            to_lang = next((l for l in installed_langs if l.code == 'en'), None)
            
            if not from_lang or not to_lang:
                logger.warning(
                    f"Translation package not available for {source_lang}->en. "
                    f"Using original text."
                )
                return {
                    'translated_text': text,
                    'original_text': text,
                    'source_language': source_lang,
                    'was_translated': False
                }
            
            translation = from_lang.get_translation(to_lang)
            if not translation:
                logger.warning(f"No translation available for {source_lang}->en")
                return {
                    'translated_text': text,
                    'original_text': text,
                    'source_language': source_lang,
                    'was_translated': False
                }
            
            translated_text = translation.translate(text)
            
            # Cache the translation
            self._translation_cache[cache_key] = translated_text
            
            logger.info(f"Translated text from {source_lang} to English")
            logger.debug(f"Original: {text[:100]}...")
            logger.debug(f"Translated: {translated_text[:100]}...")
            
            return {
                'translated_text': translated_text,
                'original_text': text,
                'source_language': source_lang,
                'was_translated': True
            }
            
        except Exception as e:
            logger.error(f"Translation failed: {e}")
            return {
                'translated_text': text,
                'original_text': text,
                'source_language': source_lang or 'unknown',
                'was_translated': False
            }


# Global translation service instance
_translation_service: Optional[TranslationService] = None


def get_translation_service(enabled: bool = True) -> TranslationService:
    """Get or create the global translation service instance.
    
    Args:
        enabled: Whether translation should be enabled
        
    Returns:
        The global TranslationService instance
    """
    global _translation_service
    if _translation_service is None:
        # Check environment variable
        env_enabled = os.getenv('MCP_SCANNER_TRANSLATION_ENABLED', 'true').lower() == 'true'
        _translation_service = TranslationService(enabled=enabled and env_enabled)
    return _translation_service


def translate_if_needed(text: str, source_lang: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function to translate text using the global service.
    
    Args:
        text: The text to translate
        source_lang: Optional source language code
        
    Returns:
        Translation result dictionary
    """
    service = get_translation_service()
    return service.translate_to_english(text, source_lang)

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

"""
Dependency Injection Container for MCP Scanner SDK.

This module provides a simple dependency injection container to improve
testability and decouple configuration from implementation.
"""

from typing import Any, Dict, Optional, Type, TypeVar

from ..config.config import Config

T = TypeVar("T")


class DIContainer:
    """Simple dependency injection container."""

    def __init__(self):
        """Initialize the container."""
        self._services: Dict[Type, Any] = {}
        self._singletons: Dict[Type, Any] = {}

    def register(
        self, service_type: Type[T], instance: T, singleton: bool = True
    ) -> None:
        """Register a service instance.

        Args:
            service_type: The type/interface to register.
            instance: The instance to register.
            singleton: Whether to treat as singleton (default: True).
        """
        if singleton:
            self._singletons[service_type] = instance
        else:
            self._services[service_type] = instance

    def register_factory(
        self, service_type: Type[T], factory: callable, singleton: bool = True
    ) -> None:
        """Register a factory function for creating instances.

        Args:
            service_type: The type/interface to register.
            factory: Factory function that creates instances.
            singleton: Whether to treat as singleton (default: True).
        """
        if singleton:
            # Create singleton instance immediately
            self._singletons[service_type] = factory()
        else:
            self._services[service_type] = factory

    def get(self, service_type: Type[T]) -> Optional[T]:
        """Get a service instance.

        Args:
            service_type: The type to retrieve.

        Returns:
            The service instance or None if not found.
        """
        # Check singletons first
        if service_type in self._singletons:
            return self._singletons[service_type]

        # Check regular services
        if service_type in self._services:
            service = self._services[service_type]
            # If it's a factory, call it
            if callable(service):
                return service()
            return service

        return None

    def get_or_create(
        self, service_type: Type[T], factory: Optional[callable] = None
    ) -> T:
        """Get a service instance or create with factory if not found.

        Args:
            service_type: The type to retrieve.
            factory: Optional factory function if service not registered.

        Returns:
            The service instance.

        Raises:
            ValueError: If service not found and no factory provided.
        """
        instance = self.get(service_type)
        if instance is not None:
            return instance

        if factory is not None:
            instance = factory()
            self.register(service_type, instance)
            return instance

        raise ValueError(
            f"Service {service_type} not registered and no factory provided"
        )

    def clear(self) -> None:
        """Clear all registered services."""
        self._services.clear()
        self._singletons.clear()


# Global container instance
_container = DIContainer()


def get_container() -> DIContainer:
    """Get the global DI container instance.

    Returns:
        The global container instance.
    """
    return _container


def configure_default_services(config: Optional[Config] = None) -> None:
    """Configure default services in the container.

    Args:
        config: Optional config instance to register.
    """
    container = get_container()

    if config:
        container.register(Config, config)


def inject_config() -> Config:
    """Inject Config dependency.

    Returns:
        Config instance from container.

    Raises:
        ValueError: If Config not registered in container.
    """
    container = get_container()
    config = container.get(Config)
    if config is None:
        raise ValueError(
            "Config not registered in DI container. Call configure_default_services() first."
        )
    return config

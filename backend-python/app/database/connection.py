from motor.motor_asyncio import AsyncIOMotorClient
from app.config.settings import settings
import logging
import os

logger = logging.getLogger(__name__)

# --- Persistent File-Based DB Wrapper ---
# Uses mongita: a MongoDB-compatible, file-backed database.
# Data survives server restarts. No separate server process needed.

import asyncio

_db_instance = None

class _MongitaWrapper:
    """Thin async wrapper around mongita's synchronous client with concurrency lock."""

    def __init__(self, path: str, db_name: str):
        from mongita import MongitaClientDisk
        self._client = MongitaClientDisk(path)
        self._db = self._client[db_name]
        self._lock = asyncio.Lock()

    def __getattr__(self, name: str):
        # Delegate attribute access to the underlying mongita db
        return _MongitaCollectionWrapper(getattr(self._db, name), self._lock)

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass


class _MongitaCollectionWrapper:
    """Makes mongita's sync collection look async (find returns cursors, etc.)."""

    def __init__(self, col, lock: asyncio.Lock):
        self._col = col
        self._lock = lock

    # --- write ops ---
    async def insert_one(self, doc):
        async with self._lock:
            return self._col.insert_one(doc)

    async def insert_many(self, docs):
        async with self._lock:
            return self._col.insert_many(docs)

    async def update_one(self, filter, update, upsert=False):
        async with self._lock:
            if upsert:
                existing = self._col.find_one(filter)
                if not existing:
                    new_doc = dict(filter)
                    if "$set" in update:
                        new_doc.update(update["$set"])
                    return self._col.insert_one(new_doc)
            return self._col.update_one(filter, update)

    async def update_many(self, filter, update):
        async with self._lock:
            return self._col.update_many(filter, update)

    async def delete_one(self, filter):
        async with self._lock:
            try:
                return self._col.delete_one(filter)
            except Exception as e:
                logger.warning(f"delete_one handled error: {e}")
                return type('DeleteResult', (), {'deleted_count': 0})()

    async def delete_many(self, filter):
        async with self._lock:
            try:
                return self._col.delete_many(filter)
            except Exception as e:
                logger.warning(f"delete_many handled error: {e}")
                count = 0
                try:
                    matching = list(self._col.find(filter or {}))
                    for m in matching:
                        try:
                            self._col.delete_one({"_id": m["_id"]})
                            count += 1
                        except Exception:
                            pass
                except Exception:
                    pass
                return type('DeleteResult', (), {'deleted_count': count})()

    # --- read ops ---
    async def find_one(self, filter=None, *args, **kwargs):
        async with self._lock:
            try:
                return self._col.find_one(filter or {})
            except Exception as e:
                logger.warning(f"find_one handled error: {e}")
                return None

    def find(self, filter=None, **kwargs):
        try:
            return _MongitaCursorWrapper(self._col.find(filter or {}), self._lock)
        except Exception as e:
            logger.warning(f"find handled error: {e}")
            return _MongitaCursorWrapper([], self._lock)

    async def count_documents(self, filter=None):
        async with self._lock:
            try:
                return self._col.count_documents(filter or {})
            except Exception as e:
                logger.warning(f"count_documents handled error: {e}")
                try:
                    return len(list(self._col.find(filter or {})))
                except Exception:
                    return 0

    async def create_index(self, keys, **kwargs):
        pass  # mongita handles indexing automatically; no-op here


class _MongitaCursorWrapper:
    """Makes mongita cursor look async with safe concurrency-locked iteration."""

    def __init__(self, cursor, lock: asyncio.Lock = None):
        self._cursor = cursor
        self._lock = lock
        self._sort_key = None
        self._sort_dir = None
        self._limit_val = None

    def sort(self, key, direction=-1):
        self._sort_key = key
        self._sort_dir = direction
        return self

    def limit(self, n):
        self._limit_val = n
        return self

    async def to_list(self, length=None):
        results = []
        if self._lock:
            async with self._lock:
                try:
                    for doc in self._cursor:
                        results.append(doc)
                except Exception as e:
                    logger.warning(f"cursor to_list iteration handled error: {e}")
        else:
            try:
                for doc in self._cursor:
                    results.append(doc)
            except Exception as e:
                logger.warning(f"cursor to_list iteration handled error: {e}")

        if self._sort_key:
            import pymongo
            from datetime import datetime, timezone
            reverse = (self._sort_dir == pymongo.DESCENDING or self._sort_dir == -1)

            def _sort_val(doc):
                v = doc.get(self._sort_key)
                if v is None:
                    return ""
                if isinstance(v, datetime):
                    if v.tzinfo is None:
                        v = v.replace(tzinfo=timezone.utc)
                    return v.isoformat()
                return str(v)

            results.sort(key=_sort_val, reverse=reverse)
        if self._limit_val is not None:
            results = results[:self._limit_val]
        if length is not None:
            results = results[:length]
        return results


    def __aiter__(self):
        self._iter = iter(list(self._cursor))
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


# --- Main Database class ---

class Database:
    client = None
    db = None

    @classmethod
    async def connect_db(cls):
        try:
            if settings.USE_MOCK_DB:
                # Use file-backed persistent DB in backend/siem_data/
                data_path = os.path.join(os.path.dirname(__file__), "..", "..", "siem_data")
                data_path = os.path.abspath(data_path)
                os.makedirs(data_path, exist_ok=True)
                logger.info(f"Using persistent file-based DB at: {data_path}")
                cls.db = _MongitaWrapper(data_path, settings.DATABASE_NAME)
            else:
                logger.info(f"Connecting to MongoDB at {settings.MONGODB_URI}")
                cls.client = AsyncIOMotorClient(settings.MONGODB_URI)
                cls.db = cls.client[settings.DATABASE_NAME]
                await cls.client.admin.command('ping')
                logger.info("Successfully connected to MongoDB")
                await cls.setup_indexes()

        except Exception as e:
            logger.error(f"Database connection failure: {e}")
            raise

    @classmethod
    async def close_db(cls):
        if cls.client:
            cls.client.close()
        elif cls.db:
            cls.db.close()
        logger.info("Database connection closed")

    @classmethod
    async def setup_indexes(cls):
        # Only needed for real MongoDB; mongita handles this automatically
        if cls.db is None or isinstance(cls.db, _MongitaWrapper):
            return

        await cls.db.users.create_index("username", unique=True)
        await cls.db.devices.create_index("device_id", unique=True)
        await cls.db.devices.create_index("hostname")
        await cls.db.devices.create_index("ip_address")
        await cls.db.devices.create_index("status")
        await cls.db.devices.create_index("last_seen")
        await cls.db.logs.create_index("timestamp")
        await cls.db.logs.create_index("device_id")
        await cls.db.logs.create_index("event_type")
        await cls.db.metrics.create_index("timestamp")
        await cls.db.metrics.create_index("device_id")
        await cls.db.processes.create_index("device_id", unique=True)
        logger.info("Database indexes setup completed")


def get_db():
    return Database.db

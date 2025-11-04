import queue
import threading
import time

# Thread-safe FIFO queue
task_queue = queue.Queue()

def worker():
    """Continuously runs and processes tasks as they arrive."""
    while True:
        task = task_queue.get()  # Wait until task is available
        if task is None:
            break
        try:
            print(f"[Queue Worker] Processing task: {task['id']}")
            task['func'](*task['args'], **task['kwargs'])  # Run the task function
        except Exception as e:
            print(f"[Queue Worker] Error processing task {task['id']}: {e}")
        finally:
            task_queue.task_done()

# Start the background worker thread
threading.Thread(target=worker, daemon=True).start()

def add_task(task_id, func, *args, **kwargs):
    """Add a new task to the queue."""
    task = {'id': task_id, 'func': func, 'args': args, 'kwargs': kwargs}
    task_queue.put(task)
    print(f"[Queue] Task {task_id} added to queue.")

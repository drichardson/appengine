// Package pullqueue reads from a pull task queue and runs a processor to handle
// each task. Pull tasks queues are described here:
// https://cloud.google.com/appengine/docs/go/taskqueue/rest/
package pullqueue

import (
	"encoding/base64"
	"errors"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	taskqueue "google.golang.org/api/taskqueue/v1beta2"
	"log"
	"strings"
	"time"
)

// Queue defines the Google Compute Platform project name and queue name.
type Queue struct {
	// The Google Cloud Platform project name.
	Project string

	// The Task Queue name
	Name string
}

// Run options.
type Options struct {
	// The duration to lease an item from a task queue.
	LeaseDuration time.Duration

	// If no items are in the queue, delay until the next check. Prevents lots of
	// requests when there's nothing to process but adds latency to the first item
	// added to an empty queue.
	NoItemsLoopDelay time.Duration
}

func (o *Options) leaseDuration() time.Duration {
	if o == nil {
		return 5 * time.Second
	}
	return o.LeaseDuration
}

func (o *Options) noItemsLoopDelay() time.Duration {
	if o == nil {
		return 10 * time.Second
	}
	return o.NoItemsLoopDelay
}

// Run runs the TaskQueueRunnner. It leases jobs from the pull task queue
// and calls processor with the tasks payload (after it has been base64 decoded).
// If processor returns nil, the task is deleted from the task queue.
// If options is nil default values will be used.
func (q *Queue) Run(c context.Context, options *Options, processor func(context.Context, []byte) error) error {
	client, err := google.DefaultClient(c, taskqueue.TaskqueueConsumerScope)
	if err != nil {
		log.Println("Error getting DefaultClient.", err)
		return err
	}
	log.Println("Got default client:", client)

	tq, err := taskqueue.New(client)
	if err != nil {
		log.Println("Error getting task queue service.", err)
		return err
	}

	log.Println("Got service:", tq)

	tqs := taskqueue.NewTasksService(tq)

	// Keep running until the context is cancelled or the dealine expires.
	for c.Err() == nil {
		log.Println("Trying to acquire lease")
		tasks, err := tqs.Lease(q.Project, q.Name, 1, int64(options.leaseDuration().Seconds())).Do()
		if err != nil {
			log.Println("Error leasing task. Sleeping.", err)
			time.Sleep(options.noItemsLoopDelay())
			log.Println("Waking up from sleep")
			continue
		}
		if len(tasks.Items) == 0 {
			log.Println("No items. Sleeping.")
			time.Sleep(options.noItemsLoopDelay())
			log.Println("Waking up from sleep")
			continue
		}

		log.Printf("Acquired lease for %v tasks of kind %v", len(tasks.Items), tasks.Kind)

		for i, task := range tasks.Items {
			log.Printf("Processing task %v with ID %v, queueName=%v", i, task.Id, task.QueueName)
			payload, err := base64.StdEncoding.DecodeString(task.PayloadBase64)
			if err != nil {
				log.Printf("Error decoding base64 payload for task ID %v. Error: %v", task.Id, err)
				continue
			}

			taskProjectName, taskQueueName, err := ParseQueueName(task)
			if err != nil {
				log.Printf("Error parsing task queue name %v", task.QueueName, err)
				continue
			}

			if err := processor(c, payload); err != nil {
				log.Printf("Error processing task ID %v. Error: %v", task.Id, err)
				continue
			}

			log.Printf("Successfully process task %v. Removing from task queue. %v, %v", task.Id, taskProjectName, taskQueueName)
			if err := tqs.Delete(taskProjectName, taskQueueName, task.Id).Do(); err != nil {
				log.Printf("Error deleting task from queue. %v", err)
				continue
			}

			log.Printf("Deleted task from queue.")
		}
	}

	return c.Err()
}

// Error code for ParseQueueName
var ErrParseError = errors.New("ErrParseError")

// ParseQueueName parses out the queue name and project name that appear in the task's
// queuename field. Queue names are prefixed (e.g., with s~) and if you don't use the prefixed
// names the task queue delete will fail with an invalid project error.
//
// Issue: https://code.google.com/p/googleappengine/issues/detail?id=10199
// task.QueueName has the format project/<prefixed_project_name>/taskqueue/<task_queue_name>
//
// Got a a bit of confirmation that this is the correct approach:
// https://github.com/google/google-api-go-client/issues/92#issuecomment-139344175
func ParseQueueName(task *taskqueue.Task) (projectName, queueName string, err error) {

	parts := strings.Split(task.QueueName, "/")
	if len(parts) != 4 {
		err = ErrParseError
		return
	}

	projectName = parts[1]
	queueName = parts[3]
	return
}

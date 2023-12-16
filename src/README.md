# Lambda function loader

## Mercan Horia & Tintu Gabriel-Claudiu 

### Implementation

    We developed an implementation that passes all tests. We added the test 10
    and test 11 refs.

####    We handled error cases, such as:
    -> non-existent lib;
    -> non-existent function;
    -> function call which gets signal (signal-catching);
    -> function call which gets exit;

####    Initial implementation for parallel:
    -> started processes on-demand which execute lambda function
        ** have a main process which interacts with IO, creates and sends
           the input to them;
        ** don't wait for workers, these will interacts with the clients
           directly, workers get exit;

####    Our idea for parallel(in progress):
    -> always active processes which get input from a main process constantly,
       through a named pipe(dont lose time for the processes loading everytime);
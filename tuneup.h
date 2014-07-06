//IO buffers count: up to 255. 
//Use high values when many simultaneous sequence writes may occur.
//Note that high value may increase CPU usage  /(TBD: optimize such situation)
//Comment if you don't need IO buffering 
//NB: buffering can be neccessary to use -d arg with SOCK_RXRING enabled
#define BUFFERS_COUNT  8				//<--option


//Sequential read tracks count: up to 255
//Defines number of sequential read track context
//Bigger values causes more parallel sequential read
//streams to be read ahead, but too high values increases CPU usage
//and value >=BUFFERS_COUNT is effectively useless
//Undefine this option if you don't need read-ahead functionality
#define READ_TRACKS		4				//<--option

//Maximum numbers of sectors that single IO buffer can hold
//The longer sequential writes may occur - the bigger value is optimal
#define BUFFERED_SECTORS		(1*1024)	//<--option

//Following value used to determine if buffer is near-to-full
//and its time to activate read-ahead or flush when possible  
//optimal value must be less than sectors count by a value
//a bit more than maximum possible MTU
#define BUFFER_FULL_THRESHOLD	((BUFFERED_SECTORS) - 64)	//<--option

//Following option slightly improves write performance by assuming 
//valid write operation always success and thus sending reply to
//client with minimal delay even client didn't specify Async write
//BTW if any write operation will fail - AoEde will instantly exit 
//to minimize risk of data corruption
#define FORCE_ASYNC_WRITES

#ifdef __linux__
//Try to use PACKET_RX_RING to receive data instead of read() call
//More CPU-effective and required for RX tags tracking (-t arg)
//However on practice not using RX ring buffer sometimes faster
//TODO: investigate why: CPU cache usage? Memory aligning?
//# define SOCK_RXRING					//<--option

//Use linux AIO to perform most IO in background
//Requres BUFFERS_COUNT>1 and valid BUFFER_FULL_THRESHOLD defined
//Note that AIO works best with direct mode (-d option)
# define USE_AIO					//<--option
#endif 


//following option enabled background 'shadow' writes while main
//blade image 'freeze'd' 
#define SHADOW_FREEZE


/////////////////////////////////////////////////////////////////////////////////
////following options designed for debug/diagnose purposes and normally disabled

//keep and print on idle some statistics information
//#define KEEP_STATS

//uncomment following line to enable random packets receive drop for debug purposes (simulate bad network)
//defined value specified how many packets must be processed normally for each dropped packet (less value -> more drops)
//#define DBG_POISON_RECV 100

//uncomment following line to enable random packets send drop for debug purposes (simulate bad network)
//defined value specified how many packets must be processed normally for each dropped packet (less value -> more drops)
//#define POISON_SEND 100

//peform validation some internal structures
//#define DBG_VALIDATE

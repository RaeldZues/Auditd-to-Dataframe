import binascii
import re 
import magic 
import gzip
import bz2
import datetime
import pandas as pd 

# TODO: Add logging functionality 

def h2a(hexdata): 
    """
    Simple helper func to convert to ascii from hex and add the proper spacing between 
    """
    try: 
        return binascii.unhexlify(hexdata).decode("ascii").replace("\x00", " ")
    except Exception as e:
        return hexdata

def h2d(hexdata: str):
    """
    Simple helper func to convert data to decimal  
    """
    try: 
        return int(hexdata, base=16)
    except Exception as e: 
        return hexdata 

def get_family(saddr):
    """
    Simple helper func to grab the family from the socket addr func
    """
    return h2d(saddr[:2]) + 256 * h2d(saddr[2:4])

def saddr_parse(saddr: str):
    """
    Helper func to parse the ip address from AF_INET and the path for AF_UNIX based families 
    TODO: Add inet6 support 
    """
    AF_LOCAL = 1
    AF_UNIX = AF_LOCAL 
    AF_INET = 2
    AF_INET6 = 28
    MAX_UNIX_PATH = 108
    family = get_family(saddr)
    # Current support only for local and inet 
    if family == AF_INET: 
        port = 256 * h2d(saddr[4:6]) + h2d(saddr[6:8])
        addr = saddr[8:]
        ip = f"{h2d(addr[:2])}.{h2d(addr[2:4])}.{h2d(addr[4:6])}.{h2d(addr[6:8])}"
        return f"{ip}:{port}"
    elif family == AF_UNIX: 
        full = list() 
        saddr = saddr[4:]
        count = 0
        for one,two in zip(saddr[::2], saddr[1::2]):
            item = one + two
            # Just grab the first null terminated string or max size unix path 
            if item == "00" or count > MAX_UNIX_PATH:
                break
            full.append(item)
            count += 1
        return h2a(''.join(full))
    else: 
        return saddr

class AuditLog():
    """
    Auditlog contains enough information to correlate the entire log between the event ids. 
    each event id has a corresponding list of event entry types (cwd, path, proctitle, syscall, execve, user_end, cred_disp) 
    TODO: Add functionality to read multiple log files, Currently only supports 1 file and overwrites 
    """
    def __init__(self):
        event_ids = set() 
        events = None 
        earliest = None
        latest = None 
        dataframes = dict()
        processes = None
        event_correlation = None
 
    def read_log(self, filename):
        """
        Reads auditd file as binary by line and creates a Base Audit Entry item for each line. 
        TODO: add mmap option to read compressed files 
        TODO: Add size limitations on the log before using mmap 
        ref: https://stackoverflow.com/questions/12660028/reading-memory-mapped-bzip2-compressed-file # subsequent links do not work 
        """
        mime = magic.Magic(mime=True)
        mimetype = mime.from_file(filename)

        if mimetype == "application/gzip":
            with gzip.open(filename, 'rb') as f: 
                lines = f.readlines()
        elif mimetype == "application/x-bzip2":
            with bz2.BZ2File(filename, "rb") as f: 
                lines = f.readlines()
                print(lines)
        else: 
            with open(filename, "rb") as f:
                lines = f.readlines()

        local_events = dict()
        times = list()
        self.event_ids = set()
        
        for line in lines: 
            entry = BaseAuditEntry(line)
            self.event_ids.add(entry.event_id)
            
            times.append(entry.timestamp)
            try:
                local_events[entry.event_type].append(entry.json_data)
            except KeyError: 
                local_events[entry.event_type] = [entry.json_data]
        
        # Meta data assistance 
        self.earliest = min(times)
        self.latest = max(times)

        ## WARNING: Overwrites previous logs if in
        self.events = local_events

    def create_dfs(self):
        """
        Iterates through the events after reading the log, converts to a pandas dataframe to expand and use in later processing. 
        """
        dataframes = dict()
        converts = {"PROCTITLE":"proctitle", "EXECVE":"a2", "USER_CMD":"cmd", "SOCKADDR":"saddr"}
        for i in self.events: 
            df = pd.DataFrame.from_records(self.events[i])
            df = pd.concat([df.drop(['message'], axis=1), df["message"].apply(pd.Series)], axis=1)
            dataframes[df.event_type.unique()[0]] = df

        # Conversion to ascii for those fields that need                 
        for k, df in dataframes.items(): 
            if k in converts.keys():
                col = converts.get(k)
                if k == "SOCKADDR":
                    df[col] = df[col].apply(saddr_parse)
                else:
                    df[col] = df[col].apply(h2a)
       
        self.dataframes = dataframes 

    def merge_process_dfs(self):
        proctitle = self.dataframes.get("PROCTITLE", pd.DataFrame())
        syscall = self.dataframes.get('SYSCALL', pd.DataFrame())
        execve = self.dataframes.get("EXECVE", pd.DataFrame())
        path = self.dataframes.get("PATH", pd.DataFrame())
        cwd = self.dataframes.get("CWD", pd.DataFrame())
        sockaddr = self.dataframes.get("SOCKADDR", pd.DataFrame())

        dfs = [proctitle, syscall, execve, path, cwd, sockaddr]
        
        if all(df is not None for df in dfs):
            # Clean the timestamp and event type and set the event_id as the idx 
            for df in dfs: 
                if df.event_type.unique()[0] == "PROCTITLE":
                    del df["event_type"]
                    continue
                if df.event_type.unique()[0] == "SOCKADDR": 
                    del df["event_type"]
                    continue 
                del df["event_type"]
                del df["timestamp"]

            
            full = proctitle.set_index("event_id")
            full = pd.merge(full, cwd, on="event_id", how='outer')
            path.set_index("event_id", inplace=True) 
            path = path.groupby("event_id").apply(lambda x: x.to_dict(orient='records'))
            full['PATH'] = path
            full = pd.merge(full, syscall, on='event_id', how="outer")
            execve.rename(columns=lambda x: re.sub('(a)(\d+)',"arg_" + '\\2',x), inplace=True)
            
            filter_col = [col for col in execve.columns if col.startswith("arg_")]
            execve["execve_cmdline"] = execve[filter_col].fillna("").apply(" ".join, axis=1).apply(lambda x: x.strip())
            execve["args"] = execve[filter_col].values.tolist()
            execve = execve.loc[:, ~execve.columns.str.startswith("arg_")]
            full = pd.merge(full, execve, on='event_id', how="outer")   
            child_procs = full[['proctitle', 'pid']].drop_duplicates()
            child_procs_dictionary = dict(zip(child_procs.pid, child_procs.proctitle))
            full['ParentProctitle'] = full.ppid.map(child_procs_dictionary)
            self.processes = full 
            
class BaseAuditEntry():
    """
    Individual line in an auditd log 
    """
    def __init__(self, line_entry):
        event_type = None
        timestamp = None 
        event_id = None
        entry = None 
        self.setup(line_entry)
        self.json_data = {"timestamp" : self.timestamp, "event_type":self.event_type, "event_id":self.event_id,  "message": self.entry }

    def setup(self, line_entry):
        # auditd uses the \x1d as a group seperator character in some of their lines, need to cleanse
        if 0x1d in line_entry:
            line_entry = line_entry.replace(b'\x1d', b" ").replace(b"\n", b"")
        # Preferance here, but i like having timestamp objects 
        self.timestamp = datetime.datetime.fromtimestamp(float(line_entry.split(b" ")[1].rstrip(b":").split(b":")[0].lstrip(b"msg=audit(")))
        
        # Event id to correlate to other audit entry types 
        self.event_id = int(line_entry.split(b" ")[1].rstrip(b":)").split(b":")[1])
        self.event_type = line_entry.split(b" ")[0].split(b"=")[1].decode('ascii')

        # If its the socket address type then clean up the line to parse easier
        if self.event_type == "SOCKADDR":
            line_entry = line_entry.replace(b"SADDR={ ", b"").replace(b" }", b"")
        
        # Setup to store as dictionary 
        line_entry = line_entry.split(b"): ")[1]
        line_entry = line_entry.replace(b"=", b":").replace(b"\n", b"").replace(b"): ", b"): {").replace(b"\"", b"").split(b" ")
        line_entry = [x.strip(b'"').split(b":") for x in line_entry ]
        
        # Note: Moving from binary to ascii below 
        # Had some empty string entries in the parsing that gets cleaned with the len below. 
        self.entry = {item[0].decode("ascii"): item[1].decode('ascii') for item in line_entry if len(item) > 1}


if __name__ == "__main__":
    log = AuditLog() 
    log.read_log("audit.log.bz2")
    log.create_dfs()
    log.merge_process_dfs()
    print(log.dataframes)

import binascii
import datetime
import pandas as pd 

def fn(foo): 
    """
    Simple helper func to convert to ascii from hex and add the proper spacing between 
    """
    try: 
        return binascii.unhexlify(foo).decode("ascii").replace("\x00", " ")
    except Exception as e:
        return foo

class AuditLog():
    def __init__(self, filename):
        event_ids = set() 
        events = None 
        earliest = None
        latest = None 
        dataframes = list()
        event_correlation = None
 
    def read_log(self):
        """
        Reads auditd file as binary by line and creates a Base Audit Entry item for each line. 
        """
        with open("audit.log", "rb") as f:
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

        # Can possibly remove this if we combine the dfs 
        self.events = local_events

    def create_dfs(self):
        """
        Iterates through the events after reading the log, converts to a pandas dataframe to expand and use in later processing. 
        """
        dataframes = list()
        for i in self.events: 
                df = pd.DataFrame.from_records(self.events[i])
                df = pd.concat([df.drop(['message'], axis=1), df["message"].apply(pd.Series)], axis=1)
                dataframes.append(df)
        # Conversion to ascii for those fields that need                 
        converts = {"PROCTITLE":"proctitle", "EXECVE":"a2", "USER_CMD":"cmd"}
        for df in dataframes: 
            if df.event_type.unique()[0] in converts.keys():
                col = converts.get(df.event_type.unique()[0])
                df[col] = df[col].apply(fn)
        self.dataframes = dataframes 

    def eventid_to_eventtype(self):
        """
        Iterates through the audit log event id list and identfies all the event types associated for correlation later 
        """
        local = dict() 
        for id in self.event_ids:
            for df in self.dataframes:
                if id in set(df.event_id):
                    etype = df.loc[df.event_id == id].iloc[0].event_type
                    try:
                        local[id].append(etype)
                    except KeyError:
                        local[id] = [etype]
        self.event_correlation = local        
        print(local)

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
        
        # Note: Transfer from binary to ascii below 
        # Had some empty string entries in the parsing that gets cleaned with the len below. 
        self.entry = {item[0].decode("ascii"): item[1].decode('ascii') for item in line_entry if len(item) > 1}


if __name__ == "__main__":
    log = AuditLog("audit.log") 
    log.read_log()
    log.create_dfs()
    for i in log.dataframes:
        print(i.head(5))
        print("")


    log.eventid_to_eventtype()
    for k,v in log.event_correlation.items():
        print(k,v)
    # TODO: since the event ids correalte so drastically to different event types, its hard to really merge a pandas dataframe completely. 
    # Figure out a better storage method and allow for easier correlation of data. 
    # TODO: Build process tree based on parent pid 
    

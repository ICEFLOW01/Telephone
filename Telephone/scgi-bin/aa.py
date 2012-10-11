#! /usr/bin/python
import scgi
import scgi.scgi_server
import time

class TimeHandler(scgi.scgi_server.SCGIHandler):
    def print_time(self, outfile):
        outfile.write("Content-Type: text/plain\r\n\r\n")
        outfile.write(time.ctime() + "\n")

    def produce(self, env, bodysize, input, output) :
        # Read arguments
        argstring = env['QUERY_STRING']
        print argstring
        # Break argument string into list of
        # pairs like "name=value"
        arglist = argstring.split('&')

        # Set up dictionary mapping argument names
        # to values
        args = {}
        #for arg in arglist:
        # (key, value) = arg.split('=')
        args = {}
        #for arg in arglist:
        # (key, value) = arg.split('=')
        # args[key] = value

        # Print time, as before, but with a bit of
        # extra advice
        outfile.write("Content-Type: text/plain\r\n\r\n")
        outfile.write(time.ctime() + "\n")
        self.print_time(output)
        output.write( "hello")

if __name__ == '__main__' :
    server = scgi.scgi_server.SCGIServer(
        handler_class=TimeHandler,
	host='172.16.16.10',
        port=3000,
    )
    server.serve()

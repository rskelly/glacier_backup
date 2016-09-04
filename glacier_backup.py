#!/usr/bin/env python

import boto3
import time
import json
import os
import hashlib
import binascii
import sys
import sqlite3
import re
import traceback
import getopt

AWS_ACCESS_KEY_ID = None
AWS_SECRET_ACCESS_KEY = None
root = None
bucket = None
vault_name = None
file_filter = None

def load_config(config):
	with open(config, 'rU') as f:
		obj = json.load(f)
		print obj
		for k, v in obj.iteritems():
			print k, v
			globals()[k] = v
	global root
	while root.endswith('/'):
		root = root[:-1]

def init_db():
	'''
	Attempt to initialize the database. This has no effect if the database is already initialized.
	'''
	conn = sqlite3.connect('glacier.db')
	c = conn.cursor()
	try:
		c.execute('create table inventory (id integer primary key, archive_id text, path text, hash text)')
		c.execute('create table files (id integer primary key, archive_id text, path text, hash text)')
		conn.commit()
	except Exception, e:
		try:
			conn.rollback()
		except: pass
		print 'Failed to create DB:', e.__str__()
	finally:
		try:
			conn.close()
		except: pass

def load_db_inventory():
	'''
	Load the inventory from the local database. This saves the effort of having to request
	an inventory from the server, but it is not guaranteed to be in synch.
	'''
	inventory = {}
	conn = sqlite3.connect('glacier.db')
	c = conn.cursor()
	try:
		for path, archive_id, hash in c.execute('select path, archive_id, hash from inventory'):
			inventory[path] = {'path' : path, 'archiveId' : archive_id, 'hash' : hash}
	except Exception, e:
		print 'Failed to load inventory:', e.__str__()
		sys.exit(1)
	finally:
		try:
			conn.close()
		except: pass
	return inventory

def load_db_files():
	'''
	Load the list of files and their hashes from the database.
	'''
	files = {}
	conn = sqlite3.connect('glacier.db')
	c = conn.cursor()
	try:
		for path, archive_id, hash in c.execute('select path, archive_id, hash from files'):
			files[path] = {'path' : path, 'archiveId' : archive_id, 'hash' : hash}
	except Exception, e:
		print 'Failed to load files:', e.__str__()
		sys.exit(1)
	finally:
		try:
			conn.close()
		except: pass
	return files

def init_client():
	'''
	Initialize the boto client.
	'''
	return boto3.client('glacier')

def start_inventory(client):
	'''
	Begin a request for the Glacier inventory.
	'''
	result = client.initiate_job(
		vaultName = vault_name,
		jobParameters = {
			'Format' : 'JSON',
			'Type' : 'inventory-retrieval',
		}
	)
	return result.get('jobId', None)

def check_inventory(client, job_id):
	''' 
	Check the status of the inventory request.
	'''
	result = client.describe_job(
		vaultName = vault_name,
		jobId = job_id
	)

	return result.get('Completed', False)

def get_inventory(client, job_id = None):
	'''
	Loads the inventory from the local database. If this fails, downloads the new inventory 
	and populates the database. In the latter case, the job_id is required.
	'''
	files = {}
	conn = sqlite3.connect('glacier.db')
	c = conn.cursor()
	try:
		# Try to build the file list.
		for path, archive_id, hash in c.execute('select path, archive_id, hash from inventory'):
			files[path] = {'path' : path, 'archiveId' : archive_id, 'hash' : hash}
	except Exception, e:
		print 'Failed to load inventory:', e.__str__()
		sys.exit(1)

	if len(files) == 0:
		result = client.get_job_output(
			vaultName = vault_name,
			jobId = job_id
		)
		tmp = json.loads(result.get('body', None).read())
		# Procude a dict keyed by the file path of each item.
		try:
			for item in tmp['ArchiveList']:
				print item
				c.execute('insert into inventory (path, archive_id, hash) values (:ArchiveDescription, :ArchiveId, :SHA256TreeHash)', item)
				files[item['ArchiveDescription']] = {'path' : item['ArchiveDescription'], 'archiveId' : item['ArchiveId'], 'hash' : item['SHA256TreeHash']}
			conn.commit()
		except Exception, e:
			try:
				conn.rollback()
			except: pass
			print 'Failed to update inventory:', e.__str__()
			sys.exit(1)
	try:
		conn.close()
	except: pass

	return files

def list_jobs(client):
	'''
	Returns a list of the current jobs.
	'''
	result = client.list_jobs(
		vaultName = vault_name,
	)
	return result

def get_inventory_job_id():
	'''
	Return the inventory job ID stored in the local file.
	'''
	try:
		with open('glacier_inventory_job_id.txt', 'r') as f:
			return f.read()
	except: pass
	return None

def save_inventory_job_id(id):
	'''
	Write the inventory job ID to the local file.
	'''
	with open('glacier_inventory_job_id.txt', 'w') as f:
		f.write(id)

def get_files(path, files, matcher):
	'''
	Recursively builds a list of files on the root
	path. The paths are absolute.
	'''
	for f in os.listdir(path):
		p = os.path.join(path, f)
		if os.path.isdir(p):
			get_files(p, files, matcher)
		elif not matcher.match(p) and os.path.getsize(p) > 0:
			files.append(p)

def get_local_files():
	'''
	Gets the list of local files and gets the hash and archive ID from the database. 
	If a file is not in the database, its hash is computed and it is added.
	'''
	files = {}
	filelst = []

	matcher = re.compile(file_filter)
	get_files(root, filelst, matcher)
	
	conn = sqlite3.connect('glacier.db')
	c = conn.cursor()
	try:
		i = 1
		for f in filelst:
			p = format_path(f)
			#print 'Getting', p
			row = c.execute('select path, archive_id, hash from files where path=?', (p,)).fetchone()
			if row and len(row) == 3:
				#print '...in db'
				if row[1]:
					#print '...already has an archive ID.'
					continue
				files[p] = {'path' : row[0], 'archiveId' : row[1], 'hash' : row[2]}
			else:
				print '...adding', f
				files[p] = {'path' : p, 'archiveId' : None, 'hash' : treehash(f)}
				c.execute('insert into files (path, hash) values (:path, :hash)', files[p])
				if i % 100 == 0:
					print 'Commit batch.'
					conn.commit()
				i = i + 1
		conn.commit()
	except Exception, e:
		try:
			conn.rollback()
		except: pass
		print 'Failed to get local files:', e.__str__()
		print traceback.format_exc()
		sys.exit(1)
	finally:
		try:
			conn.close()
		except: pass
	
	return files

def save_item(item):
	'''
	Updates a files record in the database.
	'''
	print 'Saving item:', item
	conn = sqlite3.connect('glacier.db')
	c = conn.cursor()
	try:
		c.execute('update files set archive_id=:archiveId, hash=:hash where path=:path', item)
		conn.commit()
	except Exception, e:
		try:
			conn.rollback()
		except: pass
		print 'Failed to save item:', e.__str__()
		sys.exit(1)

def format_path(path):
	'''
	Get the formatted path of the resource with the root directory
	and any extraneous path parts removed.
	'''
	p = path.replace(root, '')
	while p.startswith('/'):
		p = p[1:]
	return p

def get_new_files(client, job_id = None):
	'''
	Returns the list of files that are not currently archived.
	Rebuilds the local file and inventory databases if required.
	'''
	newfiles = {}
	local_files = get_local_files()
	print len(local_files), 'local files.'
	inventory = get_inventory(client, job_id)
	print len(inventory), 'archived files.'
	for f in local_files.keys():
		if f in inventory.keys():
			inv_hash = inventory[f]['hash']
			local_hash = local_files[f]['hash']
			# Compare the hashes.
			if inv_hash != local_hash:
				print "Hash mismatch %s:%s reuploading %s." % (inv_hash, local_hash, f)
				newfiles[f] = local_files[f]
		else:
			newfiles[f] = local_files[f]
	return newfiles

def _treehash(input):
	'''
	Computes the treehash of the input data.
	'''
	output = []
	while len(input) > 1:
		h1 = input.pop(0)
		h2 = input.pop(0)
		output.append(hashlib.sha256(h1 + h2).digest())
	if len(input) == 1:
		output.append(input.pop(0))
	if len(output) > 1:
		output = _treehash(output[:])
	return output

def treehash(filename):
	'''
	Computes the treehash from a file.

	# http://unixtastic.com/content/sha256-treehash-calculator
	'''
	hashes = []
	with open(filename,'r') as f:
		buf = f.read(1024 * 1024)
		while len(buf) != 0:
			hashes.append(hashlib.sha256(buf).digest())
			buf = f.read(1024 * 1024)
	hash = _treehash(hashes[:])
	return binascii.hexlify(hash[0])

def treehashd(data):
	'''
	Computes the treehash from a buffer.

	# http://unixtastic.com/content/sha256-treehash-calculator
	'''
	hashes = []
	chunk = 1024 * 1024
	i = 0
	buf = data[i:i + chunk]
	while len(buf) != 0:
		hashes.append(hashlib.sha256(buf).digest())
		i = i + chunk
		buf = data[i:i + chunk]
	hash = _treehash(hashes[:])
	return binascii.hexlify(hash[0])

def upload_file(client, file, hash):
	'''
	Uploads a file using the multipart strategy.
	'''
	path = os.path.join(root, file)
	print 'Uploading', path, hash
	size = 1024 * 1024 * 16
	fsize = os.path.getsize(path)
	
	response = client.initiate_multipart_upload(
   		vaultName = vault_name,
    	archiveDescription = file,
    	partSize = str(size)
    )

	upload_id = response['uploadId']

	with open(path, 'r') as f:
		data = f.read(size)
		start = 0
		end = len(data) - 1
		tries = 10
		while len(data) > 0 and tries > 0:
			try:
				print 'Uploading bytes', start, 'to', end
				checksum = treehashd(data)
				response = client.upload_multipart_part(
					vaultName = vault_name,
					uploadId = upload_id,
					range = 'bytes %d-%d/*' % (start, end),
					body = data,
					checksum = checksum
				)
				if response['checksum'] != checksum:
					raise Exception('Checksum mismatch: %s %s' % (response['checksum'], checksum))
				data = f.read(size)
				start = start + size
				end = start + len(data) - 1
			except Exception, e:
				print e.__str__()
				print "Trying again."
				tries -= 1


	tries = 10
	while tries > 0:
		try:
			print 'Completing upload...'
			response = client.complete_multipart_upload(
		 		vaultName = vault_name,
		    	uploadId = upload_id,
		    	archiveSize = str(os.path.getsize(path)),
		    	checksum = hash
			)
		except Exception, e:
			print e.__str__()
			print "Trying again."
			tries -= 1

	return response


def run(config, regenerate = False, skipInventory = False):
	'''
	Run the backup job. If regenerate is True, ignores the stored
	inventory job ID and requests a new inventory. The function will
	continue to run and wait for the job to complete, or it can
	be called again later with regenerate set to False to check the
	already-initiated job.

	The config file contains certain variables necessary to this
	function including the AWS secret and key, and locations of
	various files.
	'''
	print 'Initializing...'
	load_config(config)
	init_db()
	client = init_client()

	if not skipInventory:
		# Load the inventory job ID or None if regenerate is chosen, or
		# the ID does not exist.
		try:
			job_id = None if regenerate else get_inventory_job_id()
			print "Inventory job ID", job_id
		except: pass

		# If the job ID doesn't exist, start a new inventory job.
		if not job_id:	
			print 'Generating inventory.'
			job_id = start_inventory(client)
			save_inventory_job_id(job_id)
		if not job_id:
			raise Exception('Failed to start inventory job.')
		
		# Check for completion of the inventory job.
		while True:
			print 'Checking inventory job.'
			try:
				if check_inventory(client, job_id):
					print '...complete.'
					break
			except Exception, e:
				print e
			time.sleep(600)

		# Merge the inventory with the local database.
		print 'Getting inventory.'
		get_inventory(client, job_id)

		# Compute the list of files that have not been uploaded.
		print 'Computing upload list.'
		uploads = get_new_files(client, job_id)
		print len(uploads), ' files will be uploaded'

	# Upload files.
	print 'Uploading...'
	i = 1
	for u in uploads.values():
		print 'Uploading', i, 'of', len(uploads)
		i += 1
		result = upload_file(client, u['path'], u['hash'])
		u['archiveId'] = result['archiveId']
		save_item(u)


def usage():
	print '''
		This program backs up a set of files to an Amazon Glacier account. A local database
		is maintained, and optionally updated from the remote inventory.

		Usage: 
			./glacier_backup.py <options>

		Options:
			-r 	Generate a new inventory from the Glacier store. May take several hours
				the program can be left running or can be stopped and restarted at a 
				later time to resume. If the program is restarted, do not submit this
				flag again.
			-c	The optional config file. If it is not given, config.txt is used. 
				This file contains the user's AWS secret and key, and some general 
				configuration values.
			-i 	Skip the inventory check. This will skip requesting and/or downloading
				the inventory, and will skip checking the local files against the 
				local database. Uploading will start immediately using the local
				database as the upload file list.
	'''

if __name__ == '__main__':

	try:

		opts, args = getopt.getopt(sys.argv[1:], 'irc:', ['skip_inventory', 'regenerate', 'config='])

		regenerate = False
		skipInventory = False
		config = 'config.txt'

		for opt, arg in opts:
			if opt in ('-r', '--regenerate'):
				regenerate = True
			elif opt in ('-c', '--config'):
				config = arg
			elif opt in ('-i', '--skip_inventory'):
				skipInventory = True

		run(config, regenerate, skipInventory)

	except Exception, e:
		print e.__str__()
		usage()

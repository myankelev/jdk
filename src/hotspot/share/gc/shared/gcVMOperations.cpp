/*
 * Copyright (c) 2005, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#include "classfile/classLoaderData.hpp"
#include "classfile/javaClasses.hpp"
#include "gc/shared/allocTracer.hpp"
#include "gc/shared/gc_globals.hpp"
#include "gc/shared/gcId.hpp"
#include "gc/shared/gcLocker.hpp"
#include "gc/shared/gcVMOperations.hpp"
#include "gc/shared/softRefPolicy.hpp"
#include "interpreter/oopMapCache.hpp"
#include "logging/log.hpp"
#include "memory/classLoaderMetaspace.hpp"
#include "memory/heapInspection.hpp"
#include "memory/oopFactory.hpp"
#include "memory/universe.hpp"
#include "runtime/handles.inline.hpp"
#include "runtime/init.hpp"
#include "runtime/java.hpp"
#include "runtime/mutexLocker.hpp"
#include "utilities/dtrace.hpp"
#include "utilities/macros.hpp"
#include "utilities/preserveException.hpp"
#if INCLUDE_G1GC
#include "gc/g1/g1CollectedHeap.inline.hpp"
#include "gc/g1/g1Policy.hpp"
#endif // INCLUDE_G1GC

bool VM_Heap_Sync_Operation::doit_prologue() {
  Heap_lock->lock();
  return true;
}

void VM_Heap_Sync_Operation::doit_epilogue() {
  Heap_lock->unlock();
}

void VM_Verify::doit() {
  Universe::heap()->prepare_for_verify();
  Universe::verify();
}

VM_GC_Operation::~VM_GC_Operation() {
  CollectedHeap* ch = Universe::heap();
  ch->soft_ref_policy()->set_all_soft_refs_clear(false);
}

const char* VM_GC_Operation::cause() const {
  return GCCause::to_string(_gc_cause);
}

// The same dtrace probe can't be inserted in two different files, so we
// have to call it here, so it's only in one file.  Can't create new probes
// for the other file anymore.   The dtrace probes have to remain stable.
void VM_GC_Operation::notify_gc_begin(bool full) {
  HOTSPOT_GC_BEGIN(
                   full);
}

void VM_GC_Operation::notify_gc_end() {
  HOTSPOT_GC_END();
}

// Allocations may fail in several threads at about the same time,
// resulting in multiple gc requests.  We only want to do one of them.
bool VM_GC_Operation::skip_operation() const {
  bool skip = (_gc_count_before != Universe::heap()->total_collections());
  if (_full && skip) {
    skip = (_full_gc_count_before != Universe::heap()->total_full_collections());
  }
  return skip;
}

static bool should_use_gclocker() {
  // Only Serial and Parallel use GCLocker to synchronize with threads in JNI critical-sections, in order to handle pinned objects.
  return UseSerialGC || UseParallelGC;
}

bool VM_GC_Operation::doit_prologue() {
  assert(_gc_cause != GCCause::_no_gc, "Illegal GCCause");

  // To be able to handle a GC the VM initialization needs to be completed.
  if (!is_init_completed()) {
    vm_exit_during_initialization(
      err_msg("GC triggered before VM initialization completed. Try increasing "
              "NewSize, current value %zu%s.",
              byte_size_in_proper_unit(NewSize),
              proper_unit_for_byte_size(NewSize)));
  }


  if (should_use_gclocker()) {
    GCLocker::block();
  }
  VM_Heap_Sync_Operation::doit_prologue();

  // Check invocations
  if (skip_operation()) {
    // skip collection
    Heap_lock->unlock();
    if (should_use_gclocker()) {
      GCLocker::unblock();
    }
    _prologue_succeeded = false;
  } else {
    _prologue_succeeded = true;
  }
  return _prologue_succeeded;
}


void VM_GC_Operation::doit_epilogue() {
  // GC thread root traversal likely used OopMapCache a lot, which
  // might have created lots of old entries. Trigger the cleanup now.
  OopMapCache::try_trigger_cleanup();
  if (Universe::has_reference_pending_list()) {
    Heap_lock->notify_all();
  }
  VM_Heap_Sync_Operation::doit_epilogue();
  if (should_use_gclocker()) {
    GCLocker::unblock();
  }
}

bool VM_GC_HeapInspection::doit_prologue() {
  if (_full_gc && (UseZGC || UseShenandoahGC)) {
    // ZGC and Shenandoah cannot perform a synchronous GC cycle from within the VM thread.
    // So VM_GC_HeapInspection::collect() is a noop. To respect the _full_gc
    // flag a synchronous GC cycle is performed from the caller thread in the
    // prologue.
    Universe::heap()->collect(GCCause::_heap_inspection);
  }
  return VM_GC_Operation::doit_prologue();
}

bool VM_GC_HeapInspection::skip_operation() const {
  return false;
}

bool VM_GC_HeapInspection::collect() {
  if (GCLocker::is_active()) {
    return false;
  }
  Universe::heap()->collect_as_vm_thread(GCCause::_heap_inspection);
  return true;
}

void VM_GC_HeapInspection::doit() {
  Universe::heap()->ensure_parsability(false); // must happen, even if collection does
                                               // not happen (e.g. due to GCLocker)
                                               // or _full_gc being false
  if (_full_gc) {
    if (!collect()) {
      // The collection attempt was skipped because the gc locker is held.
      // The following dump may then be a tad misleading to someone expecting
      // only live objects to show up in the dump (see CR 6944195). Just issue
      // a suitable warning in that case and do not attempt to do a collection.
      // The latter is a subtle point, because even a failed attempt
      // to GC will, in fact, induce one in the future, which we
      // probably want to avoid in this case because the GC that we may
      // be about to attempt holds value for us only
      // if it happens now and not if it happens in the eventual
      // future.
      log_warning(gc)("GC locker is held; pre-dump GC was skipped");
    }
  }
  HeapInspection inspect;
  WorkerThreads* workers = Universe::heap()->safepoint_workers();
  if (workers != nullptr) {
    // The GC provided a WorkerThreads to be used during a safepoint.
    // Can't run with more threads than provided by the WorkerThreads.
    const uint capped_parallel_thread_num = MIN2(_parallel_thread_num, workers->max_workers());
    WithActiveWorkers with_active_workers(workers, capped_parallel_thread_num);
    inspect.heap_inspection(_out, workers);
  } else {
    inspect.heap_inspection(_out, nullptr);
  }
}

VM_CollectForMetadataAllocation::VM_CollectForMetadataAllocation(ClassLoaderData* loader_data,
                                                                 size_t size,
                                                                 Metaspace::MetadataType mdtype,
                                                                 uint gc_count_before,
                                                                 uint full_gc_count_before,
                                                                 GCCause::Cause gc_cause)
    : VM_GC_Collect_Operation(gc_count_before, gc_cause, full_gc_count_before, true),
      _result(nullptr), _size(size), _mdtype(mdtype), _loader_data(loader_data) {
  assert(_size != 0, "An allocation should always be requested with this operation.");
  AllocTracer::send_allocation_requiring_gc_event(_size * HeapWordSize, GCId::peek());
}

void VM_CollectForMetadataAllocation::doit() {
  SvcGCMarker sgcm(SvcGCMarker::FULL);

  CollectedHeap* heap = Universe::heap();
  GCCauseSetter gccs(heap, _gc_cause);

  // Check again if the space is available.  Another thread
  // may have similarly failed a metadata allocation and induced
  // a GC that freed space for the allocation.
  _result = _loader_data->metaspace_non_null()->allocate(_size, _mdtype);
  if (_result != nullptr) {
    return;
  }

#if INCLUDE_G1GC
  if (UseG1GC && ClassUnloadingWithConcurrentMark) {
    G1CollectedHeap::heap()->start_concurrent_gc_for_metadata_allocation(_gc_cause);
    // For G1 expand since the collection is going to be concurrent.
    _result = _loader_data->metaspace_non_null()->expand_and_allocate(_size, _mdtype);
    if (_result != nullptr) {
      return;
    }

    log_debug(gc)("G1 full GC for Metaspace");
  }
#endif

  // Don't clear the soft refs yet.
  heap->collect_as_vm_thread(GCCause::_metadata_GC_threshold);
  // After a GC try to allocate without expanding.  Could fail
  // and expansion will be tried below.
  _result = _loader_data->metaspace_non_null()->allocate(_size, _mdtype);
  if (_result != nullptr) {
    return;
  }

  // If still failing, allow the Metaspace to expand.
  // See delta_capacity_until_GC() for explanation of the
  // amount of the expansion.
  // This should work unless there really is no more space
  // or a MaxMetaspaceSize has been specified on the command line.
  _result = _loader_data->metaspace_non_null()->expand_and_allocate(_size, _mdtype);
  if (_result != nullptr) {
    return;
  }

  // If expansion failed, do a collection clearing soft references.
  heap->collect_as_vm_thread(GCCause::_metadata_GC_clear_soft_refs);
  _result = _loader_data->metaspace_non_null()->allocate(_size, _mdtype);
  if (_result != nullptr) {
    return;
  }

  log_debug(gc)("After Metaspace GC failed to allocate size %zu", _size);
}

VM_CollectForAllocation::VM_CollectForAllocation(size_t word_size, uint gc_count_before, GCCause::Cause cause)
    : VM_GC_Collect_Operation(gc_count_before, cause), _word_size(word_size), _result(nullptr) {
  // Only report if operation was really caused by an allocation.
  if (_word_size != 0) {
    AllocTracer::send_allocation_requiring_gc_event(_word_size * HeapWordSize, GCId::peek());
  }
}

#pragma once
#include <stdbool.h>
struct list_elem
{
	union{void* ptr; uint64_t u64;} data;
	struct list_elem* next;
};

struct list
{
	struct list_elem* head;
	struct list_elem* tail;
};

void append(struct list* l, void* data)
{
	struct list_elem* elem = malloc(sizeof(struct list_elem));
	elem->next = NULL;
	elem->data.ptr = data;
	if(l->head == NULL)
	{
		l->head = elem;
		l->tail = elem;
	}
	else
	{
		l->tail->next = elem;
		l->tail = elem;
	}
}

void append_u64(struct list* l, uint64_t data)
{
	struct list_elem* elem = malloc(sizeof(struct list_elem));
	elem->next = NULL;
	elem->data.u64 = data;
	if(l->head == NULL)
	{
		l->head = elem;
		l->tail = elem;
	}
	else
	{
		l->tail->next = elem;
		l->tail = elem;
	}
}

void clear(struct list* l)
{
	struct list_elem* curr = l->head;
	struct list_elem* next = NULL;
	while(curr != NULL)
	{
		next = curr->next;
		free(curr);
		curr = next;
	}
	l->head = NULL;
	l->tail = NULL;
}

void clear_and_delete_elements(struct list* l)
{
	struct list_elem* curr = l->head;
	struct list_elem* next = NULL;
	while(curr != NULL)
	{
		next = curr->next;
		free(curr->data.ptr);
		free(curr);
		curr = next;
	}
	l->head = NULL;
	l->tail = NULL;
}

bool list_contains(struct list* l, uint64_t elem)
{
	struct list_elem* current = l->head;
	while(current)
	{
		if(current->data.u64 == elem)
			return true;
		current = current->next;
	}
	return false;
}

bool comp_max(uint64_t a, uint64_t b)
{
	return a > b;
}

bool comp_min(uint64_t a, uint64_t b)
{
	return a < b;
}

uint64_t list_extremum(struct list* l, bool compare(uint64_t, uint64_t))
{
	struct list_elem* max_elem = l->head;
	struct list_elem* current = l->head;
	while(current)
	{
		if(compare(current->data.u64, max_elem->data.u64))
			max_elem = current;
		current = current->next;
	}
	if(max_elem)
		return max_elem->data.u64;
	else
		return 0;
}
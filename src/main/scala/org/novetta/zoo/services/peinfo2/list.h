#pragma once
#include <stdbool.h>
struct list_elem
{
	void* data;
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
	elem->data = data;
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
		free(curr->data);
		free(curr);
		curr = next;
	}
	l->head = NULL;
	l->tail = NULL;
}

bool list_contains(struct list* l, void* elem)
{
	struct list_elem* current = l->head;
	while(current)
	{
		if(current->data == elem)
			return true;
		current = current->next;
	}
	return false;
}

bool comp_max(void* a, void* b)
{
	return a > b;
}

bool comp_min(void* a, void* b)
{
	return a < b;
}

void* list_extremum(struct list* l, bool compare(void*, void*))
{
	struct list_elem* max_elem = l->head;
	struct list_elem* current = l->head;
	while(current)
	{
		if(compare(current->data, max_elem->data))
			max_elem = current;
		current = current->next;
	}
	if(max_elem)
		return max_elem->data;
	else
		return NULL;
}